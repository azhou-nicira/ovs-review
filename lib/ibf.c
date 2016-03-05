
#include <config.h>

#include "ibf.h"
#include "hash.h"


#define HASH_COUNT (3)
/* 'HASH_COUNT' number random 'basis' of hash function, used to
 * compute ibf table indexes. */
const uint32_t key_hash_bases[HASH_COUNT] = {17, 27, 39};

/* 'basis' for computing hashsum, this number should be differnet than the
  the numbers in 'key_hash_bases'. */
const uint32_t hashsum_basis = 111;

/* Hash a key into a hashsum. */
static uint32_t
ibf_hashsum_hash(const uint8_t *key, const size_t key_size)
{
    return hash_bytes(key, key_size, hashsum_basis);
}

struct ibf;
struct ibf_node {
    struct ibf *ibf;       /* The ibf it belongs to. */
    int count;
    uint32_t hashsum;
    uint8_t keysum[];      /* 'ibf_key_size()' of key array. Stores
                            * the sum of all keys encoded into this node. */
};

static size_t ibf_node_size(size_t key_size);
static size_t ibf_key_size(struct ibf_node *node);
static void ibf_node_add_key(struct ibf_node *node, const uint8_t *key);
static void ibf_node_delete_key(struct ibf_node *node, const uint8_t *key);
static bool ibf_node_is_pure(struct ibf_node *node);
static bool ibf_node_is_empty(struct ibf_node *node);

struct ibf {
     size_t key_size;            /* Size of key in bytes. */
     size_t n_nodes;             /* Size of of 'table' array, drived
                                    from the 'n_keys' arguments of
                                    ibf_create().    */
     struct ibf_node* nodes;
};

static struct ibf_node *ibf_node(const struct ibf *, size_t index);
static size_t ibf_get_key_index(const struct ibf *ibf, const uint8_t *key,
                                size_t hash_fn);
static void ibf_delete_key(struct ibf *ibf, const uint8_t *key);

struct ibf *
ibf_create(size_t key_size, size_t n_keys)
{
    struct ibf *ibf;
    size_t n_nodes;

    /* Table size = alpha * d,  alpha = 1.5  */
    n_nodes = (3 * n_keys  + 1) / 2;

    /* Make sure we can evenly split ibf table into 'HASH_COUNT'
     * partitions, So that each one of the 'HASH_COUNT' key hashes can
     * be mapped into one of the partitions, thus guarrentee the mapping
     * indexes are always distinct.  */
    n_nodes = ROUND_UP(n_nodes, HASH_COUNT);

    ibf = xzalloc(sizeof *ibf + ibf_node_size(key_size) * n_nodes);

    ibf->n_nodes = n_nodes;
    ibf->key_size = key_size;

    return ibf;
}

void
ibf_add_key(struct ibf *ibf, const uint8_t *key)
{
    size_t h;
    for (h = 0; h < HASH_COUNT; h++) {
        size_t index = ibf_get_key_index(ibf, key, h);
        ibf_node_add_key(ibf_node(ibf, index), key);
    }
}

static void
ibf_delete_key(struct ibf *ibf, const uint8_t *key)
{
    size_t h;
    for (h = 0; h < HASH_COUNT; h++) {
        size_t index = ibf_get_key_index(ibf, key, h);
        ibf_node_delete_key(ibf_node(ibf, index), key);
    }
}

static bool
ibf_is_empty(struct ibf *ibf)
{
    size_t i;
    bool empty = false;

    for (i = 0; i< ibf->n_nodes && !empty; i++) {
        empty = ibf_node_is_empty(ibf_node(ibf, i));
    }

    return empty;
}

/* Subtract 'b' from 'a'. 'b' and 'a' both IBFs that have the same
 * size and key width.  */
void
ibf_substract(struct ibf *a, const struct ibf *b)
{
    ovs_assert(a->key_size == b->key_size && a->n_nodes == b->n_nodes);
    size_t i;

    for (i = 0; i < a->n_nodes; i++) {
        struct ibf_node *anode = ibf_node(a, i);
        struct ibf_node *bnode = ibf_node(b, i);
        size_t j;

        anode->count -= bnode->count;
        anode->hashsum ^= bnode->hashsum;

        for (j = 0; j < a->key_size; j++) {
            anode->keysum[j] ^= bnode->keysum[j];
        }
    }
}

static bool
ibf_find_first_pure_node(struct ibf *ibf, size_t *index)
{
    bool pure = false;
    size_t i;

    for (i = 0; i < ibf->n_nodes && !pure; i++) {
        pure = ibf_node_is_pure(ibf_node(ibf, i));
        if (pure) {
            *index = i;
        }
    }

    return pure;
}

bool
ibf_decode(struct ibf *ibf, struct ofpbuf *added, struct ofpbuf *deleted)
{
    size_t index;
    struct ofpbuf *decoded;

    while (ibf_find_first_pure_node(ibf, &index)) {
        int c = ibf->nodes[index].count;
        uint8_t *key;

        decoded = c > 0 ? deleted : added;
        key = ofpbuf_put(decoded, &ibf->nodes[index].keysum, ibf->key_size);

        ibf_delete_key(ibf, key);
    }

    return ibf_is_empty(ibf);
}

static struct ibf_node *
ibf_node(const struct ibf *ibf, size_t index)
{
    if (index < ibf->n_nodes) {
        size_t offset = ibf_node_size(ibf->key_size) * index;

        return (void*)((char *)ibf->nodes + offset);
    }

    return NULL;
}

static size_t
ibf_get_key_index(const struct ibf *ibf, const uint8_t *key, size_t hash_fn)
{
    uint32_t hash = hash_bytes(key, ibf->key_size, key_hash_bases[hash_fn]);
    size_t part_size = ibf->n_nodes / HASH_COUNT;

    /* Ensure all 'HASH_COUNT' hashes maps into distinct indexes
     * by map each hash value uniformly into the 'i'th partition of
     * the ibf nodes.  */
    return hash_fn * part_size + hash % part_size;
}

static size_t
ibf_node_size(size_t key_size) {
    return (sizeof (struct ibf_node) + key_size);
}

static size_t
ibf_key_size(struct ibf_node * node) {
    return (node->ibf->key_size);
}

static void
ibf_node_key_op(struct ibf_node *node, const uint8_t *key, int delta)
{
    size_t i;
    size_t n = ibf_key_size(node);
    node->hashsum ^= ibf_hashsum_hash(key, ibf_key_size(node));
    for(i = 0; i < n; i++) {
        node->keysum[i] ^= key[i];
    }
    node->count += delta;
}

static void
ibf_node_add_key(struct ibf_node *node, const uint8_t *key)
{
    ibf_node_key_op(node, key, 1);
}

static void
ibf_node_delete_key(struct ibf_node *node, const uint8_t *key)
{
    ibf_node_key_op(node, key, -1);
}

static bool
ibf_node_is_empty(struct ibf_node *node){
    if (node->count == 0 && node->hashsum == 0) {
        return is_all_zeros(node->keysum, ibf_key_size(node));
    }
    return false;
}

static bool
ibf_node_is_pure(struct ibf_node *node)
{
    uint32_t hash = ibf_hashsum_hash(node->keysum, ibf_key_size(node));
    return (node->count == 1 || node->count == -1) && hash == node->hashsum;
}
