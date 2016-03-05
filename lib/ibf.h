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

#ifndef IBF_H
#define IBF_H 1

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include "hmap.h"
#include "openvswitch/dynamic-string.h"

struct ibf;

struct ibf_key_hmap_node {
    struct hmap_node hmap_node;
    uint8_t key[];
};

struct ibf_key_ops {
    void (*to_ds)(struct ds *ds, const void *key);
    uint32_t (*hash)(const void *key, uint32_t basis);
    bool (*equals)(const void *key1, const void *key2);
    void (*xor)(void *key1, const void *key2);
    bool (*is_zero)(const void *key);
};

struct ibf *ibf_create(size_t n_bytes, size_t n_elems,
                       struct ibf_key_ops *ops);
void ibf_add_key(struct ibf *ibf, void *key);
void ibf_substract(struct ibf *a, struct ibf *b);
bool ibf_decode(struct ibf *ibf, struct hmap *added, struct hmap *deleted);
void ibf_to_ds(struct ds *ds, struct ibf *ibf);


/* Strata Estimator.  */
struct ibf_strata_estimator;
struct ibf_strata_estimator * ibf_create_estimator(size_t n_ibfs,
                 unsigned int key_size, struct ibf_key_ops *key_ops);
void ibf_estimator_add_key(struct ibf_strata_estimator *, void *key);
unsigned int ibf_estimate_delta(struct ibf_strata_estimator *,
                                struct ibf_strata_estimator *);
void ibf_estimator_destroy(struct ibf_strata_estimator *);

#endif /* ibf.h */
