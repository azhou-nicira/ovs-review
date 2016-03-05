/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "hash.h"
#include "hmap.h"
#include "ibf.h"

#define HASH_COUNT (4)  /* 4 is recommanded by [1]. It is optimal when the
                           difference between data sets small, i.e.
                           (less than 30). */

/* 'HASH_COUNT' number random 'basis' of hash function, used to
 * compute ibf table indexes. */
static const uint32_t key_hash_bases[HASH_COUNT] = {17, 27, 39, 43};

/* 'basis' for computing hashsum, this number should be differnet than the
  the numbers in 'key_hash_bases'. */
static const uint32_t hashsum_basis = 111;

struct ibf_node {
    int count;
    uint32_t hashsum;
    void *keysum;           /* 'key_size' (of struct ibf) array. Stores
                            * the sum of all keys encoded into this node. */
};

static void ibf_node_add_key(struct ibf *ibf, struct ibf_node *node,
                             const void *key);
static void ibf_node_delete_key(struct ibf *ibf, struct ibf_node *node,
                                const void *key);
static bool ibf_node_is_pure(struct ibf *ibf, struct ibf_node *node);
static bool ibf_node_is_empty(struct ibf *ibf, struct ibf_node *node);

struct ibf {
     size_t key_size;            /* Size of key in bytes. */
     size_t n_nodes;             /* Size of of 'table' array, drived
                                    from the 'n_keys' arguments of
                                    ibf_create().    */
     void *keysums;              /* Buffer for keysum of all nodes. */
     struct ibf_key_ops *key_ops;/* operations on key.  */
     struct ibf_node nodes[];    /* All nodes. */
};

/* Key operations helper functions. */
static uint32_t ibf_key_hash(struct ibf *ibf, const void *key, uint32_t basis);
static uint32_t ibf_key_hashsum(struct ibf *ibf, const void *key);
static void ibf_key_xor(struct ibf *ibf, void *key1, const void *key2);
static bool ibf_key_is_zero(struct ibf *ibf, const void *key);
static void ibf_key_to_ds(struct ibf *ibf, const void *key, struct ds *ds);

static size_t ibf_get_key_index(struct ibf *ibf, const void *key, size_t i);
static void ibf_remove_key(struct ibf *ibf, const void *key);

struct ibf *
ibf_create(size_t key_size, size_t n_keys, struct ibf_key_ops *ops)
{
    struct ibf *ibf;
    size_t i, n_nodes;
    uint8_t *keysums;

    /* Table size = alpha * d,  alpha = 1.5  */
    n_nodes = (3 * n_keys  + 1) / 2;

    /* Make sure we can evenly split ibf table into 'HASH_COUNT'
     * partitions, So that each one of the 'HASH_COUNT' key hashes can
     * be mapped into one of the partitions, thus guarrentee the mapping
     * indexes are always distinct.  */
    n_nodes = ROUND_UP(n_nodes, HASH_COUNT);

    ibf = xmalloc(sizeof *ibf + n_nodes * sizeof *ibf->nodes);
    keysums = xzalloc(key_size * n_nodes);

    /* Distribute keysum pointers */
    for (i = 0; i < n_nodes; i++) {
        ibf->nodes[i].count = 0;
        ibf->nodes[i].hashsum = 0;
        ibf->nodes[i].keysum = (char *)keysums + i * key_size;
    };

    ibf->keysums = keysums;
    ibf->n_nodes = n_nodes;
    ibf->key_size = key_size;
    ibf->key_ops = ops;

    return ibf;
}

void
ibf_add_key(struct ibf *ibf, void *key)
{
    size_t i;
    for (i = 0; i < HASH_COUNT; i++) {
        size_t index = ibf_get_key_index(ibf, key, i);
        ibf_node_add_key(ibf, &ibf->nodes[index], key);
    }
}

static void
ibf_remove_key(struct ibf *ibf, const void *key)
{
    size_t i;
    for (i = 0; i < HASH_COUNT; i++) {
        size_t index = ibf_get_key_index(ibf, key, i);
        ibf_node_delete_key(ibf, &ibf->nodes[index], key);
    }
}

static bool
ibf_is_empty(struct ibf *ibf)
{
    size_t i;

    for (i = 0; i < ibf->n_nodes; i++) {
        if (!ibf_node_is_empty(ibf, &ibf->nodes[i])) {
            return false;
        }
    }
    return true;
}

/* Subtract 'b' from 'a'. 'b' and 'a' both IBFs that have the same
 * size and key width.  */
void
ibf_substract(struct ibf *a, struct ibf *b)
{
    ovs_assert(a->key_size == b->key_size && a->n_nodes == b->n_nodes);
    size_t i;

    for (i = 0; i < a->n_nodes; i++) {
        struct ibf_node *anode = &a->nodes[i];
        struct ibf_node *bnode = &b->nodes[i];

        anode->count -= bnode->count;
        anode->hashsum ^= bnode->hashsum;
        ibf_key_xor(a, anode->keysum, bnode->keysum);
    }
}

static bool
ibf_find_pure_node(struct ibf *ibf, size_t *index)
{
    size_t i;

    for (i = 0; i < ibf->n_nodes; i++) {
        if (!ibf_node_is_pure(ibf, &ibf->nodes[i])) {
            continue;
        } else {
            *index = i;
            return true;
        }
    }

    return false;
}

/* Insert unique 'key' in 'hmap'.
 */
static void *
ibf_key_hmap_insert(struct hmap *hmap, void *key, unsigned int key_size,
                    uint32_t hash)
{
    struct ibf_key_hmap_node *key_node;

    HMAP_FOR_EACH_WITH_HASH (key_node, hmap_node, hash, hmap) {
        if (!memcmp(key_node->key, key, key_size)) {
            /* The same key exists already. Return directly.  */
            return key_node->key;
        }
    }

    /* The key does not exist. Allocate a new node for it. */
    key_node = xmalloc(sizeof *key_node + key_size);
    hmap_insert(hmap, &key_node->hmap_node, hash);
    memcpy(key_node->key, key, key_size);
    return key_node->key;
}

/* Decode 'ibf' into 'added' and 'deleted' key sets.
 *
 * Algorithm summary:
 *
 * Consider two sets of keys A and B,
 *   'ibf' = ibf(A) - ibf (B)
 *
 * ibf_decode() goes throuhg all nodes in 'ibf', looking for pure nodes. Only
 * a pure node can be decoded, and its keysum is the key of the recovered
 * node. If a pure node's count is 1, the node's key is decoded as 'deleted',
 * meaning the key is in the data set of (A - B). Othersize the key is
 * int 'added', i.e. in the data set of (B - A).
 *
 * ibf_decode() stops when there isn't any pure node left.  If 'ibf' becomes
 * empty, it is decoded sucessfully,
 *
 * For details, see "What's the Difference? Efficient Set
 *  Reconciliation Without Prior Context".  by Epstein et al.
 *
 * 'added' and 'deleted' are hmaps of struct ibf_key_map_node, defined
 *  in lib/ibf.h. They are assumed to be empty, and may be uninitialized.
 *
 *  Return 'true' if 'ibf' is sucessfully decoded into 'added' and 'deleted'
 *  key sets, stored in hmap. The caller is responsible for freeing hmap
 *  nodes of both tables.
 *
 *  Return 'false' if 'ibf' can not be successfully decoded. Both 'added'
 *  and 'deleted' hamps will be empty up on return.
 */
bool
ibf_decode(struct ibf *ibf, struct hmap *added, struct hmap *deleted)
{
    size_t index;
    struct hmap *decoded;

    hmap_init(added);
    hmap_init(deleted);

    while (ibf_find_pure_node(ibf, &index)) {
        int c = ibf->nodes[index].count;
        uint8_t *key = ibf->nodes[index].keysum;
        uint32_t hash = ibf->nodes[index].hashsum;

        decoded = c > 0 ? deleted : added;
        key = ibf_key_hmap_insert(decoded, key, ibf->key_size, hash);
        ibf_remove_key(ibf, key);
    }

    bool ok = ibf_is_empty(ibf);
    if (!ok) {
        hmap_destroy(added);
        hmap_destroy(deleted);
    }

    return ok;
}


/* ibf_get_key_index in ith partition. XXX
 */
static size_t
ibf_get_key_index(struct ibf *ibf, const void *key, size_t i)
{
    uint32_t hash = ibf_key_hash(ibf, key, key_hash_bases[i]);
    const size_t part_size = ibf->n_nodes / HASH_COUNT;

    /* Ensure all 'HASH_COUNT' hashes maps into distinct indexes
     * by map each hash value uniformly into the 'i'th partition of
     * the ibf nodes.  */
    return i * part_size + hash % part_size;
}

static void
ibf_node_key_op_common(struct ibf *ibf, struct ibf_node *node,
                       const void *key, int delta)
{
    node->hashsum ^= ibf_key_hashsum(ibf, key);
    ibf_key_xor(ibf, node->keysum, key);
    node->count += delta;

}
static void
ibf_node_add_key(struct ibf *ibf, struct ibf_node *node, const void *key)
{
    ibf_node_key_op_common(ibf, node, key, 1);
}

static void
ibf_node_delete_key(struct ibf *ibf, struct ibf_node *node, const void *key)
{
    ibf_node_key_op_common(ibf, node, key, -1);
}

static bool
ibf_node_is_empty(struct ibf *ibf, struct ibf_node *node)
{
    if (!node->count && !node->hashsum) {
        return ibf_key_is_zero(ibf, node->keysum);
    }

   return false;
}

static bool
ibf_node_is_pure(struct ibf *ibf, struct ibf_node *node)
{
    if (node->count == 1 || node->count == -1) {
        return ibf_key_hashsum(ibf, node->keysum) == node->hashsum;
    }

    return false;
}

void
ibf_to_ds(struct ds *ds, struct ibf *ibf)
{
    unsigned int i;
    for (i = 0; i < ibf->n_nodes; i++) {
        struct ibf_node *node = &ibf->nodes[i];
        ds_put_format(ds, "%d: count: %d, %x ", i, node->count,
                      node->hashsum);
        ibf_key_to_ds(ibf, node->keysum, ds);
        ds_put_format(ds, "\n");
    }
}


/* Key ops helper functions. */
static uint32_t
ibf_key_hash(struct ibf *ibf, const void *key, uint32_t basis)
{
    return ibf->key_ops->hash(key, basis);
}

static void
ibf_key_xor(struct ibf *ibf, void *key1, const void *key2)
{
    ibf->key_ops->xor(key1, key2);
}

static bool
ibf_key_is_zero(struct ibf *ibf, const void *key)
{
    return ibf->key_ops->is_zero(key);
}

static void
ibf_key_to_ds(struct ibf *ibf, const void *key, struct ds *ds)
{
    ibf->key_ops->to_ds(ds, key);
}

/* Hash a key into a hashsum. */
static uint32_t
ibf_key_hashsum(struct ibf *ibf, const void *key)
{
    return ibf_key_hash(ibf, key, hashsum_basis);
}


/* Strata Estimator */
struct ibf_strata_estimator {
    size_t n_ibfs;
    struct ibf *ibfs[];
};

static const uint32_t estimator_hash_basis = 213;

struct ibf_strata_estimator *
ibf_create_estimator(size_t n_ibfs, unsigned int key_size,
                     struct ibf_key_ops *key_ops)
{
    struct ibf_strata_estimator *e;
    size_t i;

    e = xmalloc(sizeof *e + sizeof e->ibfs[0] * n_ibfs );

    for (i = 0; i < n_ibfs; i++) {
        e->ibfs[i] = ibf_create(key_size, 80, key_ops);
    }

    e->n_ibfs = n_ibfs;
    return e;
}

void
ibf_estimator_add_key(struct ibf_strata_estimator *e, void *key)
{
    uint32_t hash;
    size_t n_zeros;

    hash = ibf_key_hash(e->ibfs[0], key, estimator_hash_basis);

    if (hash) {
        n_zeros = ctz32(hash);
        if (n_zeros < e->n_ibfs) {
            ibf_add_key(e->ibfs[n_zeros], key);
        }
    }
}

unsigned int
ibf_estimate_delta(struct ibf_strata_estimator *e1,
                   struct ibf_strata_estimator *e2)
{
    unsigned int estimation = 0;
    struct hmap added, deleted;
    int idx = e1->n_ibfs;
    bool done = false;

    ovs_assert(e1->n_ibfs == e2->n_ibfs);

    while(idx-- && !done) {
        struct ibf *ibf = e1->ibfs[idx];
        ibf_substract(ibf, e2->ibfs[idx]);

        hmap_init(&added);
        hmap_init(&deleted);

        if (ibf_decode(ibf, &added, &deleted)) {
            estimation += hmap_count(&added) + hmap_count(&deleted);
        } else {
            estimation = ( (1 << idx) * estimation);
            done = true;
        }
        hmap_destroy(&added);
        hmap_destroy(&deleted);
    }

    return estimation;
}

void
ibf_estimator_destroy(struct ibf_strata_estimator *e)
{
    size_t i;

    for (i = 0; i < e->n_ibfs; i++) {
        free(e->ibfs[i]);
        e->ibfs[i] = NULL;
    }
}
