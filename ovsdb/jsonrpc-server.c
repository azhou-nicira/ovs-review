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

#include <config.h>

#include "jsonrpc-server.h"

#include <errno.h>

#include "bitmap.h"
#include "column.h"
#include "json.h"
#include "jsonrpc.h"
#include "jsonrpc-remote.h"
#include "jsonrpc-sessions.h"
#include "latch.h"
#include "monitor.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "ovsdb-parser.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "reconnect.h"
#include "row.h"
#include "server.h"
#include "simap.h"
#include "stream.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_jsonrpc_server);

DEFINE_EXTERN_PER_THREAD_DATA(per_thread_handler, NULL);

struct ovsdb_jsonrpc_remote;
struct ovsdb_jsonrpc_session;


/* Sessions handler */
struct sessions_handler {
    struct ovs_list all_sessions;  /* Holds 'ovs_jsonrpc_sessions' that runs
                                      on the same thread, */
    bool use_pthread;              /* Starts a pthread for this sessions? */

    /* The following members are not initialized if 'use_pthread' is false. */
    pthread_t thread;
    struct latch exit_latch;
};

static void sessions_handler_init(struct sessions_handler *, bool);
static void sessions_handler_destroy(struct sessions_handler *);
static struct sessions_handler *main_handler(
    const struct ovsdb_jsonrpc_server *);
static struct ovs_list *main_handler_sessions(
    const struct ovsdb_jsonrpc_server *);

/* Remotes. */
static struct ovsdb_jsonrpc_remote *ovsdb_jsonrpc_server_add_remote(
    struct ovsdb_jsonrpc_server *, const char *name,
    const struct ovsdb_jsonrpc_options *options
);
static void ovsdb_jsonrpc_server_del_remote(struct ovsdb_jsonrpc_server *,
                                            struct shash_node *);


/* JSON-RPC database server. */

/* Creates and returns a new server to provide JSON-RPC access to an OVSDB.
 *
 * 'max_threads' limits the number of threads it can create.
 *
 * The caller must call ovsdb_jsonrpc_server_add_db() for each database to
 * which 'server' should provide access.  */
struct ovsdb_jsonrpc_server *
ovsdb_jsonrpc_server_create(size_t n_max_threads)
{
    struct ovsdb_jsonrpc_server *svr = xzalloc(sizeof *svr);
    unsigned int i, n_handlers;
    ovsdb_server_init(&svr->up);
    shash_init(&svr->remotes);

    /* One handler for each thread, plus the main handler.  */
    svr->n_handlers = n_handlers = n_max_threads + 1;
    svr->handlers = xmalloc(sizeof *svr->handlers * n_handlers);
    for (i = 0; i < svr->n_handlers; i++) {
        struct sessions_handler *handler = &svr->handlers[i];
        sessions_handler_init(handler, handler != main_handler(svr));
    }

    return svr;
}

/* Adds 'db' to the set of databases served out by 'svr'.  Returns true if
 * successful, false if 'db''s name is the same as some database already in
 * 'server'. */
bool
ovsdb_jsonrpc_server_add_db(struct ovsdb_jsonrpc_server *svr, struct ovsdb *db)
{
    /* The OVSDB protocol doesn't have a way to notify a client that a
     * database has been added.  If some client tried to use the database
     * that we're adding and failed, then forcing it to reconnect seems like
     * a reasonable way to make it try again.
     *
     * If this is too big of a hammer in practice, we could be more selective,
     * e.g. disconnect only connections that actually tried to use a database
     * with 'db''s name. */
    ovsdb_jsonrpc_server_reconnect(svr);

    return ovsdb_server_add_db(&svr->up, db);
}

/* Sets 'svr''s current set of remotes to the names in 'new_remotes', with
 * options in the struct ovsdb_jsonrpc_options supplied as the data values.
 *
 * A remote is an active or passive stream connection method, e.g. "pssl:" or
 * "tcp:1.2.3.4". */
void
ovsdb_jsonrpc_server_set_remotes(struct ovsdb_jsonrpc_server *svr,
                                 const struct shash *new_remotes)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;
        struct ovsdb_jsonrpc_options *options
            = shash_find_data(new_remotes, node->name);

        if (!options) {
            VLOG_INFO("%s: remote deconfigured", node->name);
            ovsdb_jsonrpc_server_del_remote(svr, node);
        } else if (!ovsdb_jsonrpc_remote_options_can_change(remote, options)) {
            ovsdb_jsonrpc_server_del_remote(svr, node);
        }
    }
    SHASH_FOR_EACH (node, new_remotes) {
        const struct ovsdb_jsonrpc_options *options = node->data;
        struct ovsdb_jsonrpc_remote *remote;

        remote = shash_find_data(&svr->remotes, node->name);
        if (!remote) {
            remote = ovsdb_jsonrpc_server_add_remote(svr, node->name, options);
            if (!remote) {
                continue;
            }
        }

        ovsdb_jsonrpc_sessions_set_options(sessions, remote, options);
    }
}

static struct ovsdb_jsonrpc_remote *
ovsdb_jsonrpc_server_add_remote(struct ovsdb_jsonrpc_server *svr,
                                const char *name,
                                const struct ovsdb_jsonrpc_options *options)
{
    struct ovsdb_jsonrpc_remote *remote;
    struct pstream *listener;

    remote = ovsdb_jsonrpc_remote_create(svr, name, options, &listener);
    if (!remote) {
        return remote;
    }

    shash_add(&svr->remotes, name, remote);
    if (!listener) {
        ovsdb_jsonrpc_session_create(svr, jsonrpc_session_open(name, true),
                                     remote, main_handler_sessions(svr));
    }
    return remote;
}

static void
ovsdb_jsonrpc_server_del_remote(struct ovsdb_jsonrpc_server *svr,
                                 struct shash_node *node)
{
    struct ovsdb_jsonrpc_remote *remote = node->data;
    struct ovs_list *sessions;

    sessions = main_handler_sessions(svr);
    ovsdb_jsonrpc_sessions_close(sessions, remote);
    ovsdb_jsonrpc_remote_destroy(remote);
    shash_delete(&svr->remotes, node);
    free(remote);
}

/* Stores status information for the remote named 'target', which should have
 * been configured on 'svr' with a call to ovsdb_jsonrpc_server_set_remotes(),
 * into '*status'.  On success returns true, on failure (if 'svr' doesn't have
 * a remote named 'target' or if that remote is an outbound remote that has no
 * active connections) returns false.  On failure, 'status' will be zeroed.
 */
bool
ovsdb_jsonrpc_server_get_remote_status(
    const struct ovsdb_jsonrpc_server *svr, const char *target,
    struct ovsdb_jsonrpc_remote_status *status)
{
    struct ovsdb_jsonrpc_remote *remote;

    memset(status, 0, sizeof *status);
    remote = shash_find_data(&svr->remotes, target);
    if (!remote) {
        return false;
    }

    return ovsdb_jsonrpc_remote_get_status(remote, status);
}

void
ovsdb_jsonrpc_server_free_remote_status(
    struct ovsdb_jsonrpc_remote_status *status)
{
    free(status->locks_held);
    free(status->locks_waiting);
    free(status->locks_lost);
}

void
ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *svr)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        ovsdb_jsonrpc_remote_run(remote);
        ovsdb_jsonrpc_sessions_run(sessions);
    }
}

void
ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *svr)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        ovsdb_jsonrpc_remote_wait(remote);
        ovsdb_jsonrpc_sessions_wait(sessions);
    }
}

/* Removes 'db' from the set of databases served out by 'svr'.  Returns
 * true if successful, false if there is no database associated with 'db'. */
bool
ovsdb_jsonrpc_server_remove_db(struct ovsdb_jsonrpc_server *svr,
                               struct ovsdb *db)
{
    /* There might be pointers to 'db' from 'svr', such as monitors or
     * outstanding transactions.  Disconnect all JSON-RPC connections to avoid
     * accesses to freed memory.
     *
     * If this is too big of a hammer in practice, we could be more selective,
     * e.g. disconnect only connections that actually reference 'db'. */
    ovsdb_jsonrpc_server_reconnect(svr);

    return ovsdb_server_remove_db(&svr->up, db);
}

void
ovsdb_jsonrpc_server_destroy(struct ovsdb_jsonrpc_server *svr)
{
    struct shash_node *node, *next;
    unsigned int i;

    SHASH_FOR_EACH_SAFE (node, next, &svr->remotes) {
        ovsdb_jsonrpc_server_del_remote(svr, node);
    }

    for (i = 0; i < svr->n_handlers; i++) {
        sessions_handler_destroy(&svr->handlers[i]);
    }
    free(svr->handlers);

    shash_destroy(&svr->remotes);
    ovsdb_server_destroy(&svr->up);
    free(svr);
}

size_t
ovsdb_jsonrpc_server_sessions_count(struct ovsdb_jsonrpc_server *svr,
                                    struct ovsdb_jsonrpc_remote *remote)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    return ovsdb_jsonrpc_sessions_count(sessions, remote);
}

struct ovsdb_jsonrpc_options *
ovsdb_jsonrpc_default_options(const char *target)
{
    struct ovsdb_jsonrpc_options *options = xzalloc(sizeof *options);
    options->max_backoff = RECONNECT_DEFAULT_MAX_BACKOFF;
    options->probe_interval = (stream_or_pstream_needs_probes(target)
                               ? RECONNECT_DEFAULT_PROBE_INTERVAL
                               : 0);
    return options;
}

/* Forces all of the JSON-RPC sessions managed by 'svr' to disconnect and
 * reconnect. */
void
ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *svr)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        ovsdb_jsonrpc_sessions_reconnect(sessions, remote);
    }
}

/* Adds some memory usage statistics for 'svr' into 'usage', for use with
 * memory_report(). */
void
ovsdb_jsonrpc_server_get_memory_usage(const struct ovsdb_jsonrpc_server *svr,
                                      struct simap *usage)
{
    unsigned int n_sessions;

    /* The following type cast is necessary since atomic_count_get() does not
     * take a const pointer.  */
    n_sessions = atomic_count_get((struct atomic_count *)&svr->n_sessions);
    simap_increase(usage, "sessions", n_sessions);
    ovsdb_jsonrpc_sessions_get_memory_usage(main_handler_sessions(svr), usage);
}

/* Get the first session within the main handler sessions that matches
 * the 'remote'. */
struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_server_first_session(const struct ovsdb_jsonrpc_server *svr,
                                   const struct ovsdb_jsonrpc_remote *remote)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    return ovsdb_jsonrpc_sessions_first(sessions, remote);
}

void
ovsdb_jsonrpc_server_add_session(struct ovsdb_jsonrpc_server *svr,
                                 struct stream *stream,
                                 struct ovsdb_jsonrpc_remote *remote,
                                 uint8_t dscp)
{
    struct jsonrpc_session *js;

    js = jsonrpc_session_open_unreliably(jsonrpc_open(stream), dscp);
    ovsdb_jsonrpc_session_create(svr, js, remote, main_handler_sessions(svr));
}


static void *
sessions_handler_main(void * h_)
{
    struct sessions_handler *handler = h_;

    *per_thread_handler_get() = handler;
    VLOG_DBG("sessions handler thread created");
    while (!latch_is_set(&handler->exit_latch)) {
        latch_wait(&handler->exit_latch);
        poll_block();
    }
    VLOG_DBG("sessions handler thread finished");
    return NULL;
}

static void
sessions_handler_init(struct sessions_handler *handler, bool use_pthread)
{
    ovs_list_init(&handler->all_sessions);

    handler->use_pthread = use_pthread;
    if (use_pthread) {
        handler->thread = ovs_thread_create("sessions_handler",
                                            sessions_handler_main, handler);
        latch_init(&handler->exit_latch);
    } else {
        *per_thread_handler_get() = handler;
    }
}

static void
sessions_handler_destroy(struct sessions_handler *handler)
{
    ovs_assert(ovs_list_is_empty(&handler->all_sessions));

    if (handler->use_pthread) {
        latch_set(&handler->exit_latch);
        xpthread_join(handler->thread, NULL);
        latch_destroy(&handler->exit_latch);
    }
}

static struct sessions_handler *
main_handler(const struct ovsdb_jsonrpc_server *svr)
{
    return &svr->handlers[0];
}

static struct ovs_list *
main_handler_sessions(const struct ovsdb_jsonrpc_server *svr)
{
    return &main_handler(svr)->all_sessions;
}


void
ovsdb_jsonrpc_server_lock(struct ovsdb_jsonrpc_server *svr)
    OVS_ACQUIRES(svr->up.mutex)
{
    ovs_mutex_lock(&svr->up.mutex);
}

void
ovsdb_jsonrpc_server_unlock(struct ovsdb_jsonrpc_server *svr)
    OVS_RELEASES(svr->up.mutex)
{
    ovs_mutex_unlock(&svr->up.mutex);
}
