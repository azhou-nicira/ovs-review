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

#include <errno.h>
#include "bitmap.h"
#include "column.h"
#include "json.h"
#include "jsonrpc.h"
#include "jsonrpc-server.h"
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
#include "random.h"
#include "row.h"
#include "server.h"
#include "seq.h"
#include "simap.h"
#include "stream.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_jsonrpc_server);

DEFINE_EXTERN_PER_THREAD_DATA(thread_handler, NULL);

struct ovsdb_jsonrpc_remote;
struct ovsdb_jsonrpc_session;

/* Sessions handler */
struct sessions_handler {
    struct ovs_list all_sessions;  /* Holds 'ovs_jsonrpc_sessions' that runs
                                      on the same thread.  */
    unsigned int id;               /* handlers id,  mainly for logging. */

    /* IPC queue for receiving ipc messsages from other handlers. */
    struct ovs_mutex ipc_queue_mutex;
    struct ovs_list ipc_queue OVS_GUARDED; /* by 'ipc_queue_mutex' */
    struct seq *ipc_queue_seq;
    uint64_t last_ipc_seq;

    /* Those are only used when 'use_pthread' is true. */
    pthread_t thread;
    struct latch exit_latch;
};

static void sessions_handler_init(struct sessions_handler *, unsigned int);
static void sessions_handler_destroy(struct sessions_handler *);
static void sessions_handler_ipc_run(struct sessions_handler *);
static void sessions_handler_ipc_wait(struct sessions_handler *);

static struct ovs_list *handler_sessions(struct sessions_handler *handler);
static struct sessions_handler *main_handler(struct ovsdb_jsonrpc_server *);
static struct ovs_list *main_handler_sessions(struct ovsdb_jsonrpc_server *);

/* IPC message */
static char *ovsdb_ipc_to_string(struct ovsdb_ipc *ipc);

/* IPC message helper functions */
typedef void (*ovsdb_ipc_handler_t)(struct sessions_handler *,
                                    struct ovsdb_ipc *);
typedef void (*ovsdb_ipc_dtor_t)(struct ovsdb_ipc *);
typedef struct ovsdb_ipc *(*ovsdb_ipc_clone_t)(struct ovsdb_ipc *);

static struct ovsdb_ipc_ops {
    ovsdb_ipc_handler_t handler;
    ovsdb_ipc_dtor_t dtor;
    ovsdb_ipc_clone_t clone;
} ipc_ops[OVSDB_IPC_N_MESSAGES];

static struct ovsdb_ipc *ovsdb_ipc_clone(struct ovsdb_ipc *);
static struct ovsdb_ipc *ovsdb_ipc_dup(struct ovsdb_ipc *);
static struct ovsdb_ipc_ops *ipc_ops_get(enum ovsdb_ipc_type);
static void ovsdb_ipc_broadcast(struct ovsdb_jsonrpc_server *svr,
                                struct ovsdb_ipc *ipc);

/* IPC implemenation helpers. */
static void main_handler_execute_exclusive(
    struct ovsdb_jsonrpc_server *svr,
    void (*exec)(struct ovsdb_jsonrpc_server *, void *arg1, void *arg2),
    void *arg1, void *arg2);

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
        sessions_handler_init(handler, i);
    }

    return svr;
}

static inline bool
single_handler(struct ovsdb_jsonrpc_server *svr)
{
    return svr->n_handlers == 1;
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

struct ovsdb_ipc_set_options {
    struct ovsdb_ipc up;
    struct ovsdb_jsonrpc_remote *remote;
    struct ovsdb_jsonrpc_options *options;
    struct ovs_barrier *done;
};

static struct ovsdb_ipc *
ovsdb_ipc_set_options_create(struct ovsdb_jsonrpc_remote *remote,
                             struct ovsdb_jsonrpc_options *options,
                             struct ovs_barrier *done)
{
    struct ovsdb_ipc_set_options *ipc;

    ipc = xmalloc(sizeof *ipc);
    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_SET_OPTIONS, sizeof *ipc);
    ipc->remote = remote;
    ipc->options = options;
    ipc->done = done;

    return &ipc->up;
}

static void
handle_SET_OPTIONS(struct sessions_handler *handler, struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_set_options *ipc;
    struct ovs_list *sessions = handler_sessions(handler);

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_set_options, up);
    ovsdb_jsonrpc_sessions_set_options(sessions, ipc->remote, ipc->options);
    ovs_barrier_block(ipc->done);
}

static void
dtor_SET_OPTIONS(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_set_options *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_set_options, up);
    ovsdb_jsonrpc_remote_unref(ipc->remote);
    free(ipc);
}

static struct ovsdb_ipc *
clone_SET_OPTIONS(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_set_options *ipc;

    ipc = CONTAINER_OF(ovsdb_ipc_dup(ipc_), struct ovsdb_ipc_set_options, up);
    ovsdb_jsonrpc_remote_ref(ipc->remote);

    return &ipc->up;
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
        struct ovsdb_jsonrpc_options *options = node->data;
        struct ovsdb_jsonrpc_remote *remote;
        struct ovs_barrier done;

        remote = shash_find_data(&svr->remotes, node->name);
        if (!remote) {
            remote = ovsdb_jsonrpc_server_add_remote(svr, node->name, options);
            if (!remote) {
                continue;
            }
        }

        if (!single_handler(svr)) {
            struct ovsdb_ipc *ipc;
            ovs_barrier_init(&done, svr->n_handlers);
            ipc = ovsdb_ipc_set_options_create(remote, options, &done);
            ovsdb_ipc_broadcast(svr, ipc);
        }

        ovsdb_jsonrpc_sessions_set_options(main_handler_sessions(svr),
                                           remote, options);

        if (!single_handler(svr)) {
            ovs_barrier_block(&done);
            ovs_barrier_destroy(&done);
        }
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

    shash_add(&svr->remotes, name, ovsdb_jsonrpc_remote_ref(remote));
    if (!listener) {
        ovsdb_jsonrpc_session_create(svr, jsonrpc_session_open(name, true),
                                     remote, main_handler_sessions(svr));
    }
    return remote;
}

struct ovsdb_ipc_close_sessions {
    struct ovsdb_ipc up;
    struct ovsdb_jsonrpc_remote *remote;
    struct ovs_barrier *done;
};

static struct ovsdb_ipc *
ovsdb_ipc_close_sessions_create(struct ovsdb_jsonrpc_remote *remote,
                                struct ovs_barrier *done)
{
    struct ovsdb_ipc_close_sessions *ipc = xmalloc(sizeof *ipc);

    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_CLOSE_SESSIONS, sizeof *ipc);
    ipc->remote = remote;
    ipc->done = done;

    return &ipc->up;
}

static void
handle_CLOSE_SESSIONS(struct sessions_handler *handler,
                      struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_close_sessions *ipc;
    struct ovs_list *sessions = handler_sessions(handler);

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_close_sessions, up);
    ovsdb_jsonrpc_sessions_close(sessions, ipc->remote);
    ovs_barrier_block(ipc->done);
}

static void
dtor_CLOSE_SESSIONS(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_close_sessions *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_close_sessions, up);
    ovsdb_jsonrpc_remote_unref(ipc->remote);
}

static struct ovsdb_ipc *
clone_CLOSE_SESSIONS(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_close_sessions *ipc;

    ipc = CONTAINER_OF(ovsdb_ipc_dup(ipc_),
                       struct ovsdb_ipc_close_sessions, up);
    ovsdb_jsonrpc_remote_ref(ipc->remote);

    return &ipc->up;
}

static void
ovsdb_jsonrpc_server_del_remote(struct ovsdb_jsonrpc_server *svr,
                                struct shash_node *node)
{
    struct ovsdb_jsonrpc_remote *remote = node->data;
    struct ovs_barrier done;

    if (!single_handler(svr)) {
        struct ovsdb_ipc *ipc;

        ovs_barrier_init(&done, svr->n_handlers);
        ipc = ovsdb_ipc_close_sessions_create(remote, &done);
        ovsdb_ipc_broadcast(svr, ipc);
    }

    ovsdb_jsonrpc_sessions_close(main_handler_sessions(svr), remote);

    if (!single_handler(svr)) {
        ovs_barrier_block(&done);
        ovs_barrier_destroy(&done);
    }

    ovsdb_jsonrpc_remote_destroy(remote);
    shash_delete(&svr->remotes, node);
    ovsdb_jsonrpc_remote_unref(remote);
}

struct ovsdb_ipc_lock_notify {
    struct ovsdb_ipc up;
    struct ovsdb_jsonrpc_session *session;
    char *lock_name;
};

struct ovsdb_ipc *
ovsdb_ipc_lock_notify_create(struct ovsdb_jsonrpc_session *session,
                             const char *lock_name)
{
    struct ovsdb_ipc_lock_notify *ipc = xmalloc(sizeof *ipc);

    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_LOCK_NOTIFY, sizeof *ipc);
    ipc->session = ovsdb_jsonrpc_session_ref(session);
    ipc->lock_name = xstrdup(lock_name);

    return &ipc->up;
}

static void
handle_LOCK_NOTIFY(struct sessions_handler *handler, struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_lock_notify *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_lock_notify, up);
    ovsdb_jsonrpc_sessions_lock_notify(handler_sessions(handler),
                                       ipc->session, ipc->lock_name);
}

static void
dtor_LOCK_NOTIFY(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_lock_notify *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_lock_notify, up);
    free(ipc->lock_name);
    ovsdb_jsonrpc_session_unref(ipc->session);
}

static struct ovsdb_ipc *
clone_LOCK_NOTIFY(struct ovsdb_ipc *ipc_ OVS_UNUSED)
{
    /* Lock notification should never be sent to one thread at a time.
     * This function is only needed for broadcasting IPC message. So
     * it should never be called. */
    VLOG_FATAL("unexpected cloning LOCK notification IPC message");

    return NULL;
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

static void
get_sessions_count(struct ovsdb_jsonrpc_server *svr, void *remote_,
                   void *total_)
{
    struct ovsdb_jsonrpc_remote *remote = remote_;
    size_t *total = total_;
    size_t i;

    *total = 0;
    for (i = 0; i < svr->n_handlers; i++) {
        struct sessions_handler *handler = &svr->handlers[i];
        *total += ovsdb_jsonrpc_sessions_count(handler_sessions(handler),
                                               remote);
    }
}

size_t
ovsdb_jsonrpc_server_sessions_count(struct ovsdb_jsonrpc_server *svr,
                                    struct ovsdb_jsonrpc_remote *remote)
{
    size_t total;

    main_handler_execute_exclusive(svr, get_sessions_count, remote, &total);
    return total;
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

struct ovsdb_ipc_reconnect {
    struct ovsdb_ipc up;
    struct ovsdb_jsonrpc_remote *remote;
};

static struct ovsdb_ipc *
ovsdb_ipc_reconnect_create(struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_ipc_reconnect *ipc;

    ipc = xmalloc(sizeof *ipc);
    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_RECONNECT, sizeof *ipc);
    ipc->remote = remote;

    return &ipc->up;
}

static void
handle_RECONNECT(struct sessions_handler *handler, struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_reconnect *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_reconnect, up);
    ovsdb_jsonrpc_sessions_reconnect(handler_sessions(handler), ipc->remote);
}

static void
dtor_RECONNECT(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_reconnect *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_reconnect, up);
    ovsdb_jsonrpc_remote_unref(ipc->remote);
}

static struct ovsdb_ipc *
clone_RECONNECT(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_reconnect *ipc;

    ipc = CONTAINER_OF(ovsdb_ipc_dup(ipc_), struct ovsdb_ipc_reconnect, up);
    ovsdb_jsonrpc_remote_ref(ipc->remote);

    return &ipc->up;
}

/* Forces all of the JSON-RPC sessions managed by 'svr' to disconnect and
 * reconnect. */
void
ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *svr)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &svr->remotes) {
        struct ovsdb_jsonrpc_remote *remote = node->data;

        if (!single_handler(svr)) {
            struct ovsdb_ipc *ipc;
            ipc = ovsdb_ipc_reconnect_create(remote);
            ovsdb_ipc_broadcast(svr, ipc);
        }

        /* Main handler sessions */
        ovsdb_jsonrpc_sessions_reconnect(main_handler_sessions(svr),
                                         remote);
    }
}

static void
get_memory_usage(struct ovsdb_jsonrpc_server *svr, void *usage_,
                 void *unsed OVS_UNUSED)
{
    size_t i;
    struct simap *usage = usage_;

    for (i = 0; i < svr->n_handlers; i++) {
        struct sessions_handler *handler = &svr->handlers[i];
        ovsdb_jsonrpc_sessions_get_memory_usage(handler_sessions(handler),
                                                usage);
    }
}

/* Adds some memory usage statistics for 'svr' into 'usage', for use with
 * memory_report(). */
void
ovsdb_jsonrpc_server_get_memory_usage(struct ovsdb_jsonrpc_server *svr,
                                      struct simap *usage)
{
    unsigned int n_sessions;

    /* The following type cast is necessary since atomic_count_get() does not
     * take a const pointer.  */
    n_sessions = atomic_count_get((struct atomic_count *)&svr->n_sessions);
    simap_increase(usage, "sessions", n_sessions);
    main_handler_execute_exclusive(svr, get_memory_usage, usage, NULL);
}

/* Get the first session within the main handler sessions that matches
 * the 'remote'. */
struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_server_first_session(struct ovsdb_jsonrpc_server *svr,
                                   struct ovsdb_jsonrpc_remote *remote)
{
    struct ovs_list *sessions = main_handler_sessions(svr);
    return ovsdb_jsonrpc_sessions_first(sessions, remote);
}

struct ovsdb_ipc_new_session {
    struct ovsdb_ipc up;
    struct stream *stream;
    struct ovsdb_jsonrpc_remote *remote;
    struct ovsdb_jsonrpc_server *svr;
    uint8_t dscp;
};

static struct ovsdb_ipc *
ovsdb_ipc_new_session_create(struct stream *stream,
                             struct ovsdb_jsonrpc_remote *remote,
                             struct ovsdb_jsonrpc_server *svr,
                             uint8_t dscp)
{
    struct ovsdb_ipc_new_session *ipc;

    ipc = xmalloc(sizeof *ipc);
    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_NEW_SESSION, sizeof *ipc);
    ipc->stream = stream;
    ipc->remote = ovsdb_jsonrpc_remote_ref(remote);
    ipc->svr = svr;
    ipc->dscp = dscp;

    return &ipc->up;
}

static void
handle_NEW_SESSION(struct sessions_handler *handler, struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_new_session *ipc;
    struct jsonrpc_session *js;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_new_session, up);
    js = jsonrpc_session_open_unreliably(jsonrpc_open(ipc->stream), ipc->dscp);
    ovsdb_jsonrpc_session_create(ipc->svr, js, ipc->remote,
                                 handler_sessions(handler));
}

static void
dtor_NEW_SESSION(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_new_session *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_new_session, up);
    ovsdb_jsonrpc_remote_unref(ipc->remote);
}

static struct ovsdb_ipc *
clone_NEW_SESSION(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_new_session *ipc;

    ipc = CONTAINER_OF(ovsdb_ipc_dup(ipc_), struct ovsdb_ipc_new_session, up);
    ovsdb_jsonrpc_remote_ref(ipc->remote);
    return &ipc->up;
}

void
ovsdb_jsonrpc_server_add_session(struct ovsdb_jsonrpc_server *svr,
                                 struct stream *stream,
                                 struct ovsdb_jsonrpc_remote *remote,
                                 uint8_t dscp)
{
    struct sessions_handler *handler;

    /* Randomly select a handler for the new sessions. If the main
     * handler is selected, create it locally. Otherwise, send an
     * IPC message to the selected handler. */
    handler = &svr->handlers[random_uint32() % svr->n_handlers];

    if (handler == main_handler(svr)) {
        struct jsonrpc_session *js;
        js = jsonrpc_session_open_unreliably(jsonrpc_open(stream), dscp);
        ovsdb_jsonrpc_session_create(svr, js, remote,
                                     main_handler_sessions(svr));
    } else {
        struct ovsdb_ipc *ipc;
        ipc = ovsdb_ipc_new_session_create(stream, remote, svr, dscp);
        ovsdb_ipc_sendto(handler, ipc);
    }
}


static void *
sessions_handler_main(void * h_)
{
    struct sessions_handler *handler = h_;

    VLOG_DBG("sessions handler %"PRIu32" created pthread", handler->id);
    /* Intialize per thread handler pointer */
    *thread_handler_get() = handler;
    while (!latch_is_set(&handler->exit_latch)) {
        sessions_handler_ipc_run(handler);
        ovsdb_jsonrpc_sessions_run(&handler->all_sessions);

        sessions_handler_ipc_wait(handler);
        ovsdb_jsonrpc_sessions_wait(&handler->all_sessions);

        latch_wait(&handler->exit_latch);
        poll_block();
    }
    VLOG_DBG("sessions handler %"PRIu32" finished", handler->id);
    return NULL;
}

static void
sessions_handler_init(struct sessions_handler *handler, unsigned int id)
{
    ovs_list_init(&handler->all_sessions);
    ovs_mutex_init(&handler->ipc_queue_mutex);
    ovs_list_init(&handler->ipc_queue);
    handler->ipc_queue_seq = seq_create();
    handler->last_ipc_seq = seq_read(handler->ipc_queue_seq);

    handler->id = id;
    if (id) {
        handler->thread = ovs_thread_create("sessions_handler",
                                            sessions_handler_main, handler);
        latch_init(&handler->exit_latch);
    } else {
        /* Intialize per thread handler pointer for the main thread. */
        *thread_handler_get() = handler;
    }
}

static void
sessions_handler_destroy(struct sessions_handler *handler)
{
    ovs_assert(ovs_list_is_empty(&handler->all_sessions));

    if (handler->id) {
        latch_set(&handler->exit_latch);
        xpthread_join(handler->thread, NULL);
        latch_destroy(&handler->exit_latch);
    }

    ovs_mutex_destroy(&handler->ipc_queue_mutex);
    seq_destroy(handler->ipc_queue_seq);
}

static struct ovs_list *
handler_sessions(struct sessions_handler *handler)
{
    return &handler->all_sessions;
}

static struct sessions_handler *
main_handler(struct ovsdb_jsonrpc_server *svr)
{
    return &svr->handlers[0];
}

static struct ovs_list *
main_handler_sessions(struct ovsdb_jsonrpc_server *svr)
{
    return handler_sessions(main_handler(svr));
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

static void
sessions_handler_ipc_run(struct sessions_handler *handler)
{
    uint64_t new_ipc_seq;

    new_ipc_seq = seq_read(handler->ipc_queue_seq);
    if (new_ipc_seq != handler->last_ipc_seq) {
        ovs_mutex_lock(&handler->ipc_queue_mutex);
        while (!ovs_list_is_empty(&handler->ipc_queue)) {
             struct ovsdb_ipc *ipc;
             struct ovs_list *node;

             node = ovs_list_pop_front(&handler->ipc_queue);
             ipc = CONTAINER_OF(node, struct ovsdb_ipc, list);

             /* Handle IPC message. */
             ovsdb_ipc_handler_t ipc_handler;
             ipc_handler = ipc_ops_get(ipc->message)->handler;
             (*ipc_handler)(handler, ipc);

             /* Destroy IPC message. */
             ovsdb_ipc_dtor_t ipc_dtor;
             ipc_dtor = ipc_ops_get(ipc->message)->dtor;
             (*ipc_dtor)(ipc);
        }
        ovs_mutex_unlock(&handler->ipc_queue_mutex);
        handler->last_ipc_seq = new_ipc_seq;
    }
}

static void
sessions_handler_ipc_wait(struct sessions_handler *handler)
{
    seq_wait(handler->ipc_queue_seq, handler->last_ipc_seq);
}


void
ovsdb_ipc_init(struct ovsdb_ipc *ipc, enum ovsdb_ipc_type message, size_t size)
{
    ipc->message = message;
    ipc->size = size;
    ovs_list_init(&ipc->list);
}

/* Allocates memory and duplicate the content of 'ipc'.
 *
 * Note, this function does not update reference counts of pointers
 * contained within 'ipc'.  It is a helper function for implementing per
 * IPC message's clone() functions, User should call 'ovsdb_ipc_clone()'
 * instead.   */
static struct ovsdb_ipc *
ovsdb_ipc_dup(struct ovsdb_ipc *ipc)
{
    struct ovsdb_ipc *clone = xmalloc(ipc->size);
    memcpy(clone, ipc, ipc->size);
    ovs_list_init(&clone->list);

    return clone;
}

static struct ovsdb_ipc *
ovsdb_ipc_clone(struct ovsdb_ipc *ipc)
{
    ovsdb_ipc_clone_t clone = ipc_ops_get(ipc->message)->clone;
    return (*clone)(ipc);
}

static struct ovsdb_ipc_ops *
ipc_ops_get(enum ovsdb_ipc_type message)
{
    ovs_assert(message < OVSDB_IPC_N_MESSAGES);
    return &ipc_ops[message];
}

static void
ovsdb_ipc_sendto_(struct sessions_handler *handler, struct ovsdb_ipc *ipc)
{
    ovs_mutex_lock(&handler->ipc_queue_mutex);
    ovs_list_push_back(&handler->ipc_queue, &ipc->list);
    ovs_mutex_unlock(&handler->ipc_queue_mutex);
    seq_change(handler->ipc_queue_seq);
}

/* Send the 'ipc' to 'handler'. The receiving handler is responsible for
 * freeing the memory of 'ipc'.  */
void
ovsdb_ipc_sendto(struct sessions_handler *handler, struct ovsdb_ipc *ipc)
{
    if (VLOG_IS_DBG_ENABLED()) {
        char *s = ovsdb_ipc_to_string(ipc);
        struct sessions_handler *self = *thread_handler_get();
        VLOG_DBG("IPC %"PRIu32"->%"PRIu32": %s", self->id, handler->id, s);
        free(s);
    }
    ovsdb_ipc_sendto_(handler, ipc);
}

/* Broadcast the IPC message to all handlers execpt the main handler. 'ipc'
 * will be cloned for each handler. The receiving threads are responsible for
 * freeing the memory of 'ipc'.  Caller should consider 'ipc' has been freed.
 */
static void
ovsdb_ipc_broadcast(struct ovsdb_jsonrpc_server *svr,
                    struct ovsdb_ipc *ipc_)
{
    ovs_assert(!single_handler(svr));

    if (VLOG_IS_DBG_ENABLED()) {
        char *s = ovsdb_ipc_to_string(ipc_);
        struct sessions_handler *self = *thread_handler_get();
        VLOG_DBG("IPC broadcast %d: %s", self->id, s);
        free(s);
    }

    for (size_t i = 1; i < svr->n_handlers; i++) {
        struct sessions_handler *handler = &svr->handlers[i];
        struct ovsdb_ipc *ipc;

        /* Send the 'ipc_' to the last handler. Send its clones to
         * all other handlers. */
        ipc = (i != svr->n_handlers - 1) ? ovsdb_ipc_clone(ipc_) : ipc_;
        ovsdb_ipc_sendto_(handler, ipc);
    }
}

struct ovsdb_ipc_sync {
    struct ovsdb_ipc up;
    struct ovs_barrier *stop;
    struct ovs_barrier *go;
};

static struct ovsdb_ipc *
ovsdb_ipc_sync_create(struct ovs_barrier *stop, struct ovs_barrier *go)
{
    struct ovsdb_ipc_sync *ipc;

    ipc = xmalloc(sizeof *ipc);
    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_SYNC, sizeof *ipc);

    ipc->stop = stop;
    ipc->go = go;

    return &ipc->up;
}

static void
handle_SYNC(struct sessions_handler *handler OVS_UNUSED,
            struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_sync *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_sync, up);

    ovs_barrier_block(ipc->stop);
    ovs_barrier_block(ipc->go);
}

static void
dtor_SYNC(struct ovsdb_ipc *ipc_)
{
     free(ipc_);
}

static struct ovsdb_ipc *
clone_SYNC(struct ovsdb_ipc *ipc_)
{
    return ovsdb_ipc_dup(ipc_);
}

struct ovsdb_ipc_trigger {
    struct ovsdb_ipc up;
    enum ovsdb_ipc_trigger_subtype subtype;
    struct ovsdb_trigger *trigger;
};

static struct ovsdb_ipc *
ovsdb_ipc_trigger_create(enum ovsdb_ipc_trigger_subtype subtype,
                         struct ovsdb_trigger *trigger)
{
    struct ovsdb_ipc_trigger *ipc;

    ipc = xmalloc(sizeof *ipc);
    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_TRIGGER, sizeof *ipc);

    ipc->subtype = subtype;
    ipc->trigger = ovsdb_trigger_ref(trigger);

    return &ipc->up;
}

static void
handle_TRIGGER(struct sessions_handler *handler, struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_trigger *ipc;
    struct ovsdb_trigger *trigger;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_trigger, up);
    trigger = ipc->trigger;

    switch(ipc->subtype) {
    case OVSDB_IPC_TRIGGER_ADD:
        /* Only main thread should get this message. */
        ovsdb_trigger_ref(trigger);
        ovs_list_push_back(&trigger->db->triggers, &trigger->node);
        break;
    case OVSDB_IPC_TRIGGER_REMOVE:
        ovsdb_trigger_unref(trigger);
        break;
    case OVSDB_IPC_TRIGGER_COMPLETED:
        ovsdb_jsonrpc_sessions_trigger_complete(handler_sessions(handler),
                                                trigger);
        break;
    }
}

static void
dtor_TRIGGER(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_trigger *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_trigger, up);
    ovsdb_trigger_unref(ipc->trigger);
    free(ipc_);
}

static struct ovsdb_ipc *
clone_TRIGGER(struct ovsdb_ipc *ipc_ OVS_UNUSED)
{
    VLOG_FATAL("unexpected cloning trigger IPC message");
}

void
ovsdb_jsonrpc_server_trigger_completed(struct ovs_list *completed)
{
    struct ovsdb_trigger *trigger, *next;
    struct ovsdb_ipc *ipc;

    LIST_FOR_EACH_SAFE (trigger, next, node, completed) {
        struct sessions_handler *h;

        ovs_list_init(&trigger->node);
        ipc = ovsdb_ipc_trigger_create(OVSDB_IPC_TRIGGER_COMPLETED,
                                       trigger);
        h = ovsdb_jsonrpc_session_handler(trigger->session);
        ovsdb_ipc_sendto(h, ipc);
    }
}

static void
send_trigger_ipc(struct ovsdb_jsonrpc_server *svr,
                 struct ovsdb_trigger *trigger,
                 enum ovsdb_ipc_trigger_subtype subtype)
{
    struct ovsdb_ipc *ipc;
    ipc = ovsdb_ipc_trigger_create(subtype, trigger);
    ovsdb_ipc_sendto(main_handler(svr), ipc);
}

void
ovsdb_jsonrpc_server_add_trigger(struct ovsdb_jsonrpc_server *svr,
                                 struct ovsdb_trigger *trigger)
{
    send_trigger_ipc(svr, trigger, OVSDB_IPC_TRIGGER_ADD);
}

void
ovsdb_jsonrpc_server_remove_trigger(struct ovsdb_jsonrpc_server *svr,
                                    struct ovsdb_trigger *trigger)
{
    send_trigger_ipc(svr, trigger, OVSDB_IPC_TRIGGER_REMOVE);
}

struct ovsdb_ipc_monitor {
    struct ovsdb_ipc up;
    enum ovsdb_ipc_monitor_subtype subtype;
    struct ovsdb_jsonrpc_monitor *jsonrpc_monitor;
};

struct ovsdb_ipc *
ovsdb_ipc_monitor_create(enum ovsdb_ipc_monitor_subtype subtype,
                         struct ovsdb_jsonrpc_monitor *jsonrpc_monitor)
{
    struct ovsdb_ipc_monitor *ipc;

    ipc = xmalloc(sizeof *ipc);
    ovsdb_ipc_init(&ipc->up, OVSDB_IPC_MONITOR, sizeof *ipc);

    ipc->subtype = subtype;
    ipc->jsonrpc_monitor = ovsdb_jsonrpc_monitor_ref(jsonrpc_monitor);

    return &ipc->up;
}

static void
handle_MONITOR(struct sessions_handler *handler, struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_monitor *ipc;
    struct ovsdb_jsonrpc_monitor *m;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_monitor, up);
    m = ipc->jsonrpc_monitor;

    switch(ipc->subtype) {
    case OVSDB_IPC_MONITOR_SERVER_ADD:
       ovsdb_jsonrpc_monitor_server_add(m);
        break;

    case OVSDB_IPC_MONITOR_SESSION_ADD:
        ovsdb_jsonrpc_monitor_session_add(handler_sessions(handler), m);
        break;

    case OVSDB_IPC_MONITOR_SERVER_REMOVE:
        ovsdb_jsonrpc_monitor_server_remove(m);
        break;

    case OVSDB_IPC_MONITOR_SESSION_REMOVE:
        ovsdb_jsonrpc_monitor_session_remove(handler_sessions(handler), m);
        break;
    }
}

static void
dtor_MONITOR(struct ovsdb_ipc *ipc_)
{
    struct ovsdb_ipc_monitor *ipc;

    ipc = CONTAINER_OF(ipc_, struct ovsdb_ipc_monitor, up);
    ovsdb_jsonrpc_monitor_unref(ipc->jsonrpc_monitor);
    free(ipc_);
}

static struct ovsdb_ipc *
clone_MONITOR(struct ovsdb_ipc *ipc_ OVS_UNUSED)
{
    VLOG_FATAL("unexpected cloning monitor IPC message");
}

/* Sync all handlers before execute 'exec'.
 *
 * This is a helper function for using OVSDB_IPC_SYNC.
 *
 * For servers with a single handler, 'exec' is called directly.
 *
 * For servers with mulitple handlers, A OVSDB_IPC_SYNC will be broadcasted
 * to all threads ( non-main handlers), to ensure 'exec' is executed
 * race free.
 */
static void
main_handler_execute_exclusive(struct ovsdb_jsonrpc_server *svr,
                               void (*exec)(struct ovsdb_jsonrpc_server *,
                                            void *arg1, void *arg2),
                               void* arg1, void *arg2)
{
    if (single_handler(svr)) {
        (*exec)(svr, arg1, arg2);
        return;
    }

    struct ovsdb_ipc *ipc;
    struct ovs_barrier stop, go;

    ovs_barrier_init(&stop, svr->n_handlers);
    ovs_barrier_init(&go, svr->n_handlers);

    ipc = ovsdb_ipc_sync_create(&stop, &go);
    ovsdb_ipc_broadcast(svr, ipc);

    ovs_barrier_block(&stop);
    (*exec)(svr, arg1, arg2);
    ovs_barrier_block(&go);

    ovs_barrier_destroy(&stop);
    ovs_barrier_destroy(&go);
}

static const char *
ovsdb_ipc_msg_type_to_string(enum ovsdb_ipc_type ipc_type)
{
    switch (ipc_type) {
    case OVSDB_IPC_SYNC:
        return "sync";
    case OVSDB_IPC_NEW_SESSION:
        return "new_session";
    case OVSDB_IPC_CLOSE_SESSIONS:
        return "close_sessions";
    case OVSDB_IPC_RECONNECT:
        return "reconnect";
    case OVSDB_IPC_SET_OPTIONS:
        return "set_options";
    case OVSDB_IPC_LOCK_NOTIFY:
        return "lock";
    case OVSDB_IPC_TRIGGER:
        return "trigger";
    case OVSDB_IPC_MONITOR:
        return "monitor";
    case OVSDB_IPC_N_MESSAGES:
    default:
        ovs_fatal(0, "Not a valid IPC message");
    }
}

static void
ovsdb_ipc_to_ds(struct ovsdb_ipc *ipc, struct ds *ds)
{
    ds_put_cstr(ds, ovsdb_ipc_msg_type_to_string(ipc->message));
}

static char *
ovsdb_ipc_to_string(struct ovsdb_ipc *ipc)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ovsdb_ipc_to_ds(ipc, &ds);
    return ds_steal_cstr(&ds);
}

static struct ovsdb_ipc_ops ipc_ops[OVSDB_IPC_N_MESSAGES] = {
#define OVSDB_IPC_MESSAGE(MSG) {handle_##MSG, dtor_##MSG, clone_##MSG},
    OVSDB_IPC_MESSAGES
#undef OVSDB_IPC_MESSAGE
};

void
ovsdb_jsonrpc_server_get_threads_info(struct ds *ds,
                                      struct ovsdb_jsonrpc_server *svr)
{
     ds_put_format(ds, "Number of sessions handlers: %"PRIu32",", svr->n_handlers);
     ds_put_format(ds, "Number of sessions: %"PRIu32"",
                   atomic_count_get((struct atomic_count *)&svr->n_sessions));
}
