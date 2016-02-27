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


#ifndef OVSDB_JSONRPC_REMOTE_H
#define OVSDB_JSONRPC_REMOTE_H 1

#include <stdbool.h>
#include "jsonrpc-server.h"

struct ovsdb_jsonrpc_remote;
struct ovsdb_jsonrpc_options;
struct pstream;

struct ovsdb_jsonrpc_remote *
ovsdb_jsonrpc_remote_create(struct ovsdb_jsonrpc_server *svr,
                            const char *name,
                            const struct ovsdb_jsonrpc_options *options,
                            struct pstream **listener);
void ovsdb_jsonrpc_remote_destroy(struct ovsdb_jsonrpc_remote *remote);

struct ovsdb_jsonrpc_server * ovsdb_jsonrpc_remote_get_server(
    struct ovsdb_jsonrpc_remote *remote);

bool ovsdb_jsonrpc_remote_get_status(
    struct ovsdb_jsonrpc_remote *remote,
    struct ovsdb_jsonrpc_remote_status *status);

void ovsdb_jsonrpc_remote_run(struct ovsdb_jsonrpc_remote *remote);
void ovsdb_jsonrpc_remote_wait(struct ovsdb_jsonrpc_remote *remote);

bool ovsdb_jsonrpc_remote_options_can_change(
    const struct ovsdb_jsonrpc_remote *remote,
    const struct ovsdb_jsonrpc_options *new_options);

uint8_t ovsdb_jsonrpc_remote_dscp(const struct ovsdb_jsonrpc_remote *);
#endif /* ovsdb/jsonrpc-remote.h */
