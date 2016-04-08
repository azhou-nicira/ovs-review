/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef OVSDB_JSONRPC_SERVER_H
#define OVSDB_JSONRPC_SERVER_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/types.h"
#include "server.h"

struct ovsdb;
struct shash;
struct simap;
struct stream;
struct ovs_list;
struct ovsdb_jsonrpc_remote;
struct sessions_handler;

/* Sessions_handler. */
struct sessions_handler {
    struct ovs_list all_sessions;  /* List of 'ovsdb_jsonrpc_session's.   */
};

/* JSON-RPC database server. */
struct ovsdb_jsonrpc_server {
    struct ovsdb_server up;
    unsigned int n_sessions;
    struct shash remotes;      /* Contains "struct ovsdb_jsonrpc_remote *"s. */

    /* Handlers for 'ovs_list' that contains 'ovsdb_jsonrpc_sessions'.
     *
     * Each 'handler' handles a set of ovdb_jsonrpc_sessions.
     * When OVSDB runs in a multi-threaded environment, there will be
     * exactly 'n + 1' handlers for 'n' threads.  Each thread owns
     * one handler, plus the main handler owned by the main process.
     * the main process's handler is called the 'main handler'.
     *
     * The 'main handler' is always the first handler of the array.
     *
     * The handlers are statically allocated for the server; they
     * are crated when ovsdb_jsonrpc_server is crated.  Once created,
     * both 'n_handlers' and 'handlers' are never changed or moved until
     * the server is destroyed.    */
    struct sessions_handler *handlers;
    unsigned int n_handlers;
};

struct ovsdb_jsonrpc_server *ovsdb_jsonrpc_server_create(void);
bool ovsdb_jsonrpc_server_add_db(struct ovsdb_jsonrpc_server *,
                                 struct ovsdb *);
bool ovsdb_jsonrpc_server_remove_db(struct ovsdb_jsonrpc_server *,
                                     struct ovsdb *);
void ovsdb_jsonrpc_server_destroy(struct ovsdb_jsonrpc_server *);

/* Options for a remote. */
struct ovsdb_jsonrpc_options {
    int max_backoff;            /* Maximum reconnection backoff, in msec. */
    int probe_interval;         /* Max idle time before probing, in msec. */
    int dscp;                   /* DSCP value for manager connections */
};
struct ovsdb_jsonrpc_options *
ovsdb_jsonrpc_default_options(const char *target);

void ovsdb_jsonrpc_server_set_remotes(struct ovsdb_jsonrpc_server *,
                                      const struct shash *);

/* Status of a single remote connection. */
struct ovsdb_jsonrpc_remote_status {
    const char *state;
    int last_error;
    unsigned int sec_since_connect;
    unsigned int sec_since_disconnect;
    bool is_connected;
    char *locks_held;
    char *locks_waiting;
    char *locks_lost;
    int n_connections;
    ovs_be16 bound_port;
};

bool ovsdb_jsonrpc_server_get_remote_status(
    const struct ovsdb_jsonrpc_server *, const char *target,
    struct ovsdb_jsonrpc_remote_status *);
void ovsdb_jsonrpc_server_free_remote_status(
    struct ovsdb_jsonrpc_remote_status *);

void ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *);

void ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *);
void ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *);
size_t ovsdb_jsonrpc_server_sessions_count(
    struct ovsdb_jsonrpc_server *, struct ovsdb_jsonrpc_remote *);

struct ovsdb_jsonrpc_session *ovsdb_jsonrpc_server_first_session(
    const struct ovsdb_jsonrpc_server *, const struct ovsdb_jsonrpc_remote *);

void ovsdb_jsonrpc_server_get_memory_usage(const struct ovsdb_jsonrpc_server *,
                                           struct simap *usage);

void ovsdb_jsonrpc_server_add_session(struct ovsdb_jsonrpc_server *,
                                      struct stream *,
                                      struct ovsdb_jsonrpc_remote *,
                                      uint8_t dscp);

#endif /* ovsdb/jsonrpc-server.h */
