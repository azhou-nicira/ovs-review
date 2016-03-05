/* Copyright (c) 2016 Nicira, Inc.
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
#include "openvswitch/ofpbuf.h"

struct ibf;

struct ibf *ibf_create(size_t n_bytes, size_t n_elems);
void ibf_add_key(struct ibf *ibf, const uint8_t *element);
void ibf_substract(struct ibf *a, const struct ibf *b);
bool ibf_decode(struct ibf *ibf, struct ofpbuf *added, struct ofpbuf *deleted);

#endif
