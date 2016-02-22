/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#ifndef OVSDB_JSONRPC_SESSIONS_H
#define OVSDB_JSONRPC_SESSIONS_H 1

struct ovs_list;
struct ovsdb_jsonrpc_remote;
struct ovsdb_jsonrpc_options;
struct sessions_handler;


/* Session set. */
void ovsdb_jsonrpc_sessions_run(struct ovs_list *);
void ovsdb_jsonrpc_sessions_wait(struct ovs_list *);
void ovsdb_jsonrpc_sessions_close(struct ovs_list *,
                                  const struct ovsdb_jsonrpc_remote *);
void ovsdb_jsonrpc_sessions_reconnect(struct ovs_list *,
                                      const struct ovsdb_jsonrpc_remote *);
void ovsdb_jsonrpc_sessions_get_memory_usage(const struct ovs_list *,
                                             struct simap *);
void ovsdb_jsonrpc_sessions_set_options(struct ovs_list *,
                                        const struct ovsdb_jsonrpc_remote *,
                                        const struct ovsdb_jsonrpc_options *);
size_t ovsdb_jsonrpc_sessions_count(const struct ovs_list *,
                                    const struct ovsdb_jsonrpc_remote *);
struct ovsdb_jsonrpc_session *ovsdb_jsonrpc_sessions_first(
    const struct ovs_list *, const struct ovsdb_jsonrpc_remote *);
void ovsdb_jsonrpc_sessions_add(struct ovs_list *,
                                struct ovsdb_jsonrpc_session *);

/* Monitor */
struct ovsdb_jsonrpc_monitor;
void ovsdb_jsonrpc_monitor_destroy(struct ovsdb_jsonrpc_monitor *);
void ovsdb_jsonrpc_disable_monitor2(void);

/* Session. */
void ovsdb_jsonrpc_session_get_status(
    const struct ovsdb_jsonrpc_session *session,
    struct ovsdb_jsonrpc_remote_status *status);

struct ovsdb_jsonrpc_session *ovsdb_jsonrpc_session_create(
    struct ovsdb_jsonrpc_server *server, struct jsonrpc_session *js,
    struct ovsdb_jsonrpc_remote *remote, struct ovs_list *sessions);

#endif /* ovsdb/jsonrpc-session.h */
