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

#include <config.h>

#include <errno.h>
#include "bitmap.h"
#include "column.h"
#include "json.h"
#include "jsonrpc.h"
#include "jsonrpc-remote.h"
#include "jsonrpc-sessions.h"
#include "monitor.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "ovsdb-error.h"
#include "ovsdb.h"
#include "ovsdb-parser.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "reconnect.h"
#include "row.h"
#include "server.h"
#include "seq.h"
#include "simap.h"
#include "stream.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"

struct sessions_handler;

VLOG_DEFINE_THIS_MODULE(ovsdb_jsonrpc_sessions);

struct ovsdb_jsonrpc_session {
    struct ovs_list node;       /* Element in remote's sessions list. */
    struct ovsdb_session up;
    const struct ovsdb_jsonrpc_remote *remote;
    struct ovsdb_jsonrpc_server *server;

    /* Triggers. */
    struct hmap triggers;       /* Hmap of "struct ovsdb_jsonrpc_trigger"s. */

    /* Monitors. */
    struct hmap monitors;       /* Hmap of "struct ovsdb_jsonrpc_monitor"s. */

    /* Network connectivity. */
    struct jsonrpc_session *js;  /* JSON-RPC session. */
    unsigned int js_seqno;       /* Last jsonrpc_session_get_seqno() value. */

    /* Multi-threading.  */
    struct ovs_refcount refcount; /* Opaque pointer reference counter.  */
    unsigned int thread_id; /* The thread that created the session.
                               This thread has exclusive access to the
                               session. Other thread may use pointer to
                               this session as opaue pointer. */
    struct sessions_handler *handler;
};

/* Sessions. */
static void ovsdb_jsonrpc_session_unlock_all(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_unlock__(struct ovsdb_lock_waiter *);
static void ovsdb_jsonrpc_session_send(struct ovsdb_jsonrpc_session *,
                                       struct jsonrpc_msg *);
static void ovsdb_jsonrpc_session_close(struct ovsdb_jsonrpc_session *);
static int ovsdb_jsonrpc_session_run(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_wait(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_session_get_memory_usage(
    const struct ovsdb_jsonrpc_session *, struct simap *usage);
static void ovsdb_jsonrpc_session_got_request(struct ovsdb_jsonrpc_session *,
                                             struct jsonrpc_msg *);
static void ovsdb_jsonrpc_session_got_notify(struct ovsdb_jsonrpc_session *,
                                             struct jsonrpc_msg *);

/* Triggers. */
static void ovsdb_jsonrpc_trigger_create(struct ovsdb_jsonrpc_session *,
                                         struct ovsdb *,
                                         struct json *id, struct json *params);
static struct ovsdb_jsonrpc_trigger *ovsdb_jsonrpc_trigger_find(
    struct ovsdb_jsonrpc_session *, const struct json *id, size_t hash);
static void ovsdb_jsonrpc_trigger_complete(struct ovsdb_jsonrpc_trigger *);
static void ovsdb_jsonrpc_trigger_complete_all(struct ovsdb_jsonrpc_session *);

/* Monitors. */
static struct jsonrpc_msg *ovsdb_jsonrpc_monitor_create(
    struct ovsdb_jsonrpc_session *, struct ovsdb *, struct json *params,
    enum ovsdb_monitor_version, const struct json *request_id);
static struct jsonrpc_msg *ovsdb_jsonrpc_monitor_cancel(
    struct ovsdb_jsonrpc_session *,
    struct json_array *params,
    const struct json *request_id);
static void ovsdb_jsonrpc_monitor_remove_all(struct ovsdb_jsonrpc_session *);
static void ovsdb_jsonrpc_monitor_flush_all(struct ovsdb_jsonrpc_session *);
static bool ovsdb_jsonrpc_monitor_needs_flush(struct ovsdb_jsonrpc_session *);
static struct json *ovsdb_jsonrpc_monitor_compose_update(
    struct ovsdb_jsonrpc_monitor *monitor, bool initial);
static struct ovsdb_jsonrpc_monitor * ovsdb_jsonrpc_monitor_find(
    struct ovsdb_jsonrpc_session *s, const struct json *monitor_id);

static bool monitor2_enable__ = true;


static int
ovsdb_jsonrpc_session_run(struct ovsdb_jsonrpc_session *s)
{
    jsonrpc_session_run(s->js);
    if (s->js_seqno != jsonrpc_session_get_seqno(s->js)) {
        s->js_seqno = jsonrpc_session_get_seqno(s->js);
        ovsdb_jsonrpc_trigger_complete_all(s);
        ovsdb_jsonrpc_monitor_remove_all(s);
        ovsdb_jsonrpc_session_unlock_all(s);
    }

    if (!jsonrpc_session_get_backlog(s->js)) {
        struct jsonrpc_msg *msg;

        ovsdb_jsonrpc_monitor_flush_all(s);

        msg = jsonrpc_session_recv(s->js);
        if (msg) {
            if (msg->type == JSONRPC_REQUEST) {
                ovsdb_jsonrpc_session_got_request(s, msg);
            } else if (msg->type == JSONRPC_NOTIFY) {
                ovsdb_jsonrpc_session_got_notify(s, msg);
            } else {
                VLOG_WARN("%s: received unexpected %s message",
                          jsonrpc_session_get_name(s->js),
                          jsonrpc_msg_type_to_string(msg->type));
                jsonrpc_session_force_reconnect(s->js);
                jsonrpc_msg_destroy(msg);
            }
        }
    }
    return jsonrpc_session_is_alive(s->js) ? 0 : ETIMEDOUT;
}

static void
ovsdb_jsonrpc_session_set_options(struct ovsdb_jsonrpc_session *session,
                                  const struct ovsdb_jsonrpc_options *options)
{
    jsonrpc_session_set_max_backoff(session->js, options->max_backoff);
    jsonrpc_session_set_probe_interval(session->js, options->probe_interval);
    jsonrpc_session_set_dscp(session->js, options->dscp);
}

static void
ovsdb_jsonrpc_session_wait(struct ovsdb_jsonrpc_session *s)
{
    jsonrpc_session_wait(s->js);
    if (!jsonrpc_session_get_backlog(s->js)) {
        if (ovsdb_jsonrpc_monitor_needs_flush(s)) {
            poll_immediate_wake();
        } else {
            jsonrpc_session_recv_wait(s->js);
        }
    }
}

static void
ovsdb_jsonrpc_session_get_memory_usage(const struct ovsdb_jsonrpc_session *s,
                                       struct simap *usage)
{
    simap_increase(usage, "triggers", hmap_count(&s->triggers));
    simap_increase(usage, "backlog", jsonrpc_session_get_backlog(s->js));
}

void
ovsdb_jsonrpc_session_get_status(const struct ovsdb_jsonrpc_session *session,
                                 struct ovsdb_jsonrpc_remote_status *status)
{
    const struct ovsdb_jsonrpc_session *s = session;
    const struct jsonrpc_session *js;
    struct ovsdb_lock_waiter *waiter;
    struct reconnect_stats rstats;
    struct ds locks_held, locks_waiting, locks_lost;

    js = s->js;

    status->is_connected = jsonrpc_session_is_connected(js);
    status->last_error = jsonrpc_session_get_status(js);

    jsonrpc_session_get_reconnect_stats(js, &rstats);
    status->state = rstats.state;
    status->sec_since_connect = rstats.msec_since_connect == UINT_MAX
        ? UINT_MAX : rstats.msec_since_connect / 1000;
    status->sec_since_disconnect = rstats.msec_since_disconnect == UINT_MAX
        ? UINT_MAX : rstats.msec_since_disconnect / 1000;

    ds_init(&locks_held);
    ds_init(&locks_waiting);
    ds_init(&locks_lost);
    HMAP_FOR_EACH (waiter, session_node, &s->up.waiters) {
        struct ds *string;

        string = (ovsdb_lock_waiter_is_owner(waiter) ? &locks_held
                  : waiter->mode == OVSDB_LOCK_WAIT ? &locks_waiting
                  : &locks_lost);
        if (string->length) {
            ds_put_char(string, ' ');
        }
        ds_put_cstr(string, waiter->lock_name);
    }
    status->locks_held = ds_steal_cstr(&locks_held);
    status->locks_waiting = ds_steal_cstr(&locks_waiting);
    status->locks_lost = ds_steal_cstr(&locks_lost);
}

/* Lookup db using locking. This function can be called
 * from any thread. If a 'db' is found, it is reference counted
 * so that both 'db' and 'db->schema' are safe to access
 * by the same thread that did the look up.
 *
 * The caller is responsible for calling ovsdb_unref() when disposing
 * the returned pointer.  */
static struct ovsdb *
lookup_db__(const struct ovsdb_jsonrpc_session *s, const char *db_name)
{
    struct ovsdb *db;

    ovsdb_jsonrpc_server_lock(s->server);
    db = ovsdb_ref(shash_find_data(&s->up.server->dbs, db_name));
    ovsdb_jsonrpc_server_unlock(s->server);

    return db;
}

/* Examines 'request' to determine the database to which it relates, and then
 * searches 's' to find that database:
 *
 *    - If successful, returns the database and sets '*replyp' to NULL.
 *
 *    - If no such database exists, returns NULL and sets '*replyp' to an
 *      appropriate JSON-RPC error reply, owned by the caller. */
static struct ovsdb *
ovsdb_jsonrpc_lookup_db(const struct ovsdb_jsonrpc_session *s,
                        const struct jsonrpc_msg *request,
                        struct jsonrpc_msg **replyp)
{
    struct json_array *params;
    struct ovsdb_error *error;
    const char *db_name;
    struct ovsdb *db;

    params = json_array(request->params);
    if (!params->n || params->elems[0]->type != JSON_STRING) {
        error = ovsdb_syntax_error(
            request->params, NULL,
            "%s request params must begin with <db-name>", request->method);
        goto error;
    }

    db_name = params->elems[0]->u.string;
    db = lookup_db__(s, db_name);
    if (!db) {
        error = ovsdb_syntax_error(
            request->params, "unknown database",
            "%s request specifies unknown database %s",
            request->method, db_name);
        goto error;
    }

    *replyp = NULL;
    return db;

error:
    *replyp = jsonrpc_create_error(ovsdb_error_to_json(error), request->id);
    ovsdb_error_destroy(error);
    return NULL;
}

static struct ovsdb_error *
ovsdb_jsonrpc_session_parse_lock_name(const struct jsonrpc_msg *request,
                                      const char **lock_namep)
{
    const struct json_array *params;

    params = json_array(request->params);
    if (params->n != 1 || params->elems[0]->type != JSON_STRING ||
        !ovsdb_parser_is_id(json_string(params->elems[0]))) {
        *lock_namep = NULL;
        return ovsdb_syntax_error(request->params, NULL,
                                  "%s request params must be <id>",
                                  request->method);
    }

    *lock_namep = json_string(params->elems[0]);
    return NULL;
}

static void
ovsdb_jsonrpc_session_notify(struct ovsdb_session *session,
                             const char *lock_name,
                             const char *method)
{
    struct ovsdb_jsonrpc_session *s;
    struct json *params;

    s = CONTAINER_OF(session, struct ovsdb_jsonrpc_session, up);
    if (ovsdb_jsonrpc_session_handled_locally(s)) {
        params = json_array_create_1(json_string_create(lock_name));
        ovsdb_jsonrpc_session_send(s, jsonrpc_create_notify(method, params));
    } else {
        struct ovsdb_ipc *ipc;
        ipc = ovsdb_ipc_lock_notify_create(s, lock_name);
        ovsdb_ipc_sendto(s->handler, ipc);
    }
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_session_lock(struct ovsdb_jsonrpc_session *s,
                           struct jsonrpc_msg *request,
                           enum ovsdb_lock_mode mode)
{
    struct ovsdb_lock_waiter *waiter;
    struct jsonrpc_msg *reply;
    struct ovsdb_error *error;
    struct ovsdb_session *victim;
    const char *lock_name;
    struct json *result;

    error = ovsdb_jsonrpc_session_parse_lock_name(request, &lock_name);
    if (error) {
        goto error;
    }

    /* Report error if this session has issued a "lock" or "steal" without a
     * matching "unlock" for this lock. */
    waiter = ovsdb_session_get_lock_waiter(&s->up, lock_name);
    if (waiter) {
        error = ovsdb_syntax_error(
            request->params, NULL,
            "must issue \"unlock\" before new \"%s\"", request->method);
        goto error;
    }

    /* Get the lock, add us as a waiter. */
    waiter = ovsdb_server_lock(s->up.server, &s->up, lock_name, mode, &victim);
    if (victim) {
        ovsdb_jsonrpc_session_notify(victim, lock_name, "stolen");
    }

    result = json_object_create();
    json_object_put(result, "locked",
                    json_boolean_create(ovsdb_lock_waiter_is_owner(waiter)));

    return jsonrpc_create_reply(result, request->id);

error:
    reply = jsonrpc_create_error(ovsdb_error_to_json(error), request->id);
    ovsdb_error_destroy(error);
    return reply;
}

static void
ovsdb_jsonrpc_session_unlock_all(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_lock_waiter *waiter, *next;

    HMAP_FOR_EACH_SAFE (waiter, next, session_node, &s->up.waiters) {
        ovsdb_jsonrpc_session_unlock__(waiter);
    }
}

static void
ovsdb_jsonrpc_session_unlock__(struct ovsdb_lock_waiter *waiter)
{
    struct ovsdb_lock *lock = waiter->lock;

    if (lock) {
        ovs_mutex_lock(&lock->mutex);
        struct ovsdb_session *new_owner = ovsdb_lock_waiter_remove(lock, waiter);

        if (new_owner) {
            ovsdb_jsonrpc_session_notify(new_owner, lock->name, "locked");
        } else {
            /* ovsdb_server_lock() might have freed 'lock'. */
        }
        ovs_mutex_unlock(&lock->mutex);
    }

    ovsdb_lock_waiter_destroy(waiter);
}

void
ovsdb_jsonrpc_sessions_lock_notify(struct ovs_list *sessions,
                                   struct ovsdb_jsonrpc_session *session,
                                   const char *lock_name)
{
    struct ovsdb_jsonrpc_session *s;

    LIST_FOR_EACH (s, node, sessions) {
        /* Only handle lock notification if the session is still alive
         * within the handler. If the session has been deleted, send
         * notification to the next waiter. */
        if (s == session) {
            struct ovsdb_lock_waiter *waiter;

            waiter = ovsdb_session_get_lock_waiter(&s->up, lock_name);
            ovs_assert(waiter);

            ovsdb_jsonrpc_session_unlock__(waiter);
        }
    }
    /* Ignore the message if the session has been deleted already.
       The sesion deletion should have unlocked this lock.  */
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_session_unlock(struct ovsdb_jsonrpc_session *s,
                             struct jsonrpc_msg *request)
{
    struct ovsdb_lock_waiter *waiter;
    struct jsonrpc_msg *reply;
    struct ovsdb_error *error;
    const char *lock_name;

    error = ovsdb_jsonrpc_session_parse_lock_name(request, &lock_name);
    if (error) {
        goto error;
    }

    /* Report error if this session has not issued a "lock" or "steal" for this
     * lock. */
    waiter = ovsdb_session_get_lock_waiter(&s->up, lock_name);
    if (!waiter) {
        error = ovsdb_syntax_error(
            request->params, NULL, "\"unlock\" without \"lock\" or \"steal\"");
        goto error;
    }

    ovsdb_jsonrpc_session_unlock__(waiter);

    return jsonrpc_create_reply(json_object_create(), request->id);

error:
    reply = jsonrpc_create_error(ovsdb_error_to_json(error), request->id);
    ovsdb_error_destroy(error);
    return reply;
}

static struct jsonrpc_msg *
execute_transaction(struct ovsdb_jsonrpc_session *s, struct ovsdb *db,
                    struct jsonrpc_msg *request)
{
    ovsdb_jsonrpc_trigger_create(s, db, request->id, request->params);
    request->id = NULL;
    request->params = NULL;
    jsonrpc_msg_destroy(request);
    return NULL;
}

static void
ovsdb_jsonrpc_session_got_request(struct ovsdb_jsonrpc_session *s,
                                  struct jsonrpc_msg *request)
{
    struct jsonrpc_msg *reply;

    if (!strcmp(request->method, "transact")) {
        struct ovsdb *db = ovsdb_jsonrpc_lookup_db(s, request, &reply);
        if (!reply) {
            reply = execute_transaction(s, db, request);
        }
        ovsdb_unref(db);
    } else if (!strcmp(request->method, "monitor") ||
               (monitor2_enable__ && !strcmp(request->method, "monitor2"))) {
        struct ovsdb *db = ovsdb_jsonrpc_lookup_db(s, request, &reply);
        if (!reply) {
            int l = strlen(request->method) - strlen("monitor");
            enum ovsdb_monitor_version version = l ? OVSDB_MONITOR_V2
                                                   : OVSDB_MONITOR_V1;
            reply = ovsdb_jsonrpc_monitor_create(s, db, request->params,
                                                 version, request->id);
        }
        ovsdb_unref(db);
    } else if (!strcmp(request->method, "monitor_cancel")) {
        reply = ovsdb_jsonrpc_monitor_cancel(s, json_array(request->params),
                                             request->id);
    } else if (!strcmp(request->method, "get_schema")) {
        struct ovsdb *db = ovsdb_jsonrpc_lookup_db(s, request, &reply);
        if (!reply) {
            reply = jsonrpc_create_reply(ovsdb_schema_to_json(db->schema),
                                         request->id);
        }
        ovsdb_unref(db);
    } else if (!strcmp(request->method, "list_dbs")) {
        size_t n_dbs;
        struct shash_node *node;
        struct json **dbs;
        size_t i;

        ovsdb_jsonrpc_server_lock(s->server);
        n_dbs = shash_count(&s->up.server->dbs);
        dbs = xmalloc(n_dbs * sizeof *dbs);
        i = 0;
        SHASH_FOR_EACH (node, &s->up.server->dbs) {
            dbs[i++] = json_string_create(node->name);
        }
        ovsdb_jsonrpc_server_unlock(s->server);
        reply = jsonrpc_create_reply(json_array_create(dbs, n_dbs),
                                     request->id);
    } else if (!strcmp(request->method, "lock")) {
        reply = ovsdb_jsonrpc_session_lock(s, request, OVSDB_LOCK_WAIT);
    } else if (!strcmp(request->method, "steal")) {
        reply = ovsdb_jsonrpc_session_lock(s, request, OVSDB_LOCK_STEAL);
    } else if (!strcmp(request->method, "unlock")) {
        reply = ovsdb_jsonrpc_session_unlock(s, request);
    } else if (!strcmp(request->method, "echo")) {
        reply = jsonrpc_create_reply(json_clone(request->params), request->id);
    } else {
        reply = jsonrpc_create_error(json_string_create("unknown method"),
                                     request->id);
    }

    if (reply) {
        jsonrpc_msg_destroy(request);
        ovsdb_jsonrpc_session_send(s, reply);
    }
}

static void
execute_cancel(struct ovsdb_jsonrpc_session *s, struct jsonrpc_msg *request)
{
    if (json_array(request->params)->n == 1) {
        struct ovsdb_jsonrpc_trigger *t;
        struct json *id;

        id = request->params->u.array.elems[0];
        t = ovsdb_jsonrpc_trigger_find(s, id, json_hash(id, 0));
        if (t) {
            ovsdb_jsonrpc_trigger_complete(t);
        }
    }
}

static void
ovsdb_jsonrpc_session_got_notify(struct ovsdb_jsonrpc_session *s,
                                 struct jsonrpc_msg *request)
{
    if (!strcmp(request->method, "cancel")) {
        execute_cancel(s, request);
    }
    jsonrpc_msg_destroy(request);
}

static void
ovsdb_jsonrpc_session_send(struct ovsdb_jsonrpc_session *s,
                           struct jsonrpc_msg *msg)
{
    ovsdb_jsonrpc_monitor_flush_all(s);
    jsonrpc_session_send(s->js, msg);
}

struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_session_create(struct ovsdb_jsonrpc_server *server,
                             struct jsonrpc_session *js,
                             struct ovsdb_jsonrpc_remote *remote,
                             struct ovs_list *sessions)
{
    struct ovsdb_jsonrpc_session *s;

    s = xzalloc(sizeof *s);
    ovsdb_session_init(&s->up, &server->up);
    s->remote = remote;
    s->server = server;
    hmap_init(&s->triggers);
    hmap_init(&s->monitors);
    s->js = js;
    s->js_seqno = jsonrpc_session_get_seqno(js);
    ovs_refcount_init(&s->refcount);
    ovsdb_jsonrpc_sessions_add(sessions, s);
    s->thread_id = ovsthread_id_self();
    s->handler = *thread_handler_get();

    /* Let server know about session membership change.  */
    atomic_count_inc(&server->n_sessions);
    return s;
}

static void
ovsdb_jsonrpc_session_close(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_server *server = s->server;

    ovsdb_jsonrpc_monitor_remove_all(s);
    ovsdb_jsonrpc_session_unlock_all(s);
    ovsdb_jsonrpc_trigger_complete_all(s);

    hmap_destroy(&s->monitors);
    hmap_destroy(&s->triggers);

    jsonrpc_session_close(s->js);
    ovsdb_session_destroy(&s->up);

    /* Let server know about session membership change.  */
    atomic_count_dec(&server->n_sessions);

    ovs_list_remove(&s->node);
    ovsdb_jsonrpc_session_unref(s);
}


/* JSON-RPC database server triggers.
 *
 * (Every transaction is treated as a trigger even if it doesn't actually have
 * any "wait" operations.) */

struct ovsdb_jsonrpc_trigger {
    struct ovsdb_trigger trigger;
    struct hmap_node hmap_node; /* In session's "triggers" hmap. */
    struct json *id;
};

static void
ovsdb_jsonrpc_trigger_create(struct ovsdb_jsonrpc_session *s, struct ovsdb *db,
                             struct json *id, struct json *params)
{
    struct ovsdb_jsonrpc_trigger *t;
    struct ovsdb_jsonrpc_server *server;
    size_t hash;

    /* Check for duplicate ID. */
    hash = json_hash(id, 0);
    t = ovsdb_jsonrpc_trigger_find(s, id, hash);
    if (t) {
        struct jsonrpc_msg *msg;

        msg = jsonrpc_create_error(json_string_create("duplicate request ID"),
                                   id);
        ovsdb_jsonrpc_session_send(s, msg);
        json_destroy(id);
        json_destroy(params);
        return;
    }

    /* Insert into trigger table. */
    t = xmalloc(sizeof *t);
    ovsdb_trigger_init(&s->up, db, &t->trigger, params, time_msec());
    t->id = id;
    hmap_insert(&s->triggers, &t->hmap_node, hash);
    server = CONTAINER_OF(s->up.server, struct ovsdb_jsonrpc_server, up);
    ovsdb_jsonrpc_server_add_trigger(server, &t->trigger);

    /* Complete early if possible. */
    if (ovsdb_trigger_is_complete(&t->trigger)) {
        ovsdb_jsonrpc_trigger_complete(t);
    }
}

static struct ovsdb_jsonrpc_trigger *
ovsdb_jsonrpc_trigger_find(struct ovsdb_jsonrpc_session *s,
                           const struct json *id, size_t hash)
{
    struct ovsdb_jsonrpc_trigger *t;

    HMAP_FOR_EACH_WITH_HASH (t, hmap_node, hash, &s->triggers) {
        if (json_equal(t->id, id)) {
            return t;
        }
    }

    return NULL;
}

static void
ovsdb_jsonrpc_trigger_complete(struct ovsdb_jsonrpc_trigger *t)
{
    struct ovsdb_jsonrpc_session *s;

    s = CONTAINER_OF(t->trigger.session, struct ovsdb_jsonrpc_session, up);

    if (jsonrpc_session_is_connected(s->js)) {
        struct jsonrpc_msg *reply;
        struct json *result;

        result = ovsdb_trigger_steal_result(&t->trigger);
        if (result) {
            reply = jsonrpc_create_reply(result, t->id);
        } else {
            struct ovsdb_jsonrpc_server *svr;
            reply = jsonrpc_create_error(json_string_create("canceled"),
                                         t->id);
            /* Since trigger does not have result yet, the main
             * thread may still have it. Send an IPC message to remove
             * it from the main thread. */
            svr = CONTAINER_OF(t->trigger.session->server,
                               struct ovsdb_jsonrpc_server, up);
            ovsdb_jsonrpc_server_remove_trigger(svr, &t->trigger);
        }
        ovsdb_jsonrpc_session_send(s, reply);
    }

    json_destroy(t->id);
    hmap_remove(&s->triggers, &t->hmap_node);
    ovsdb_trigger_unref(&t->trigger);
}

static void
ovsdb_jsonrpc_trigger_complete_all(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_trigger *t, *next;
    HMAP_FOR_EACH_SAFE (t, next, hmap_node, &s->triggers) {
        ovsdb_jsonrpc_trigger_complete(t);
    }
}

void
ovsdb_jsonrpc_sessions_trigger_complete(struct ovs_list *sessions,
                                        struct ovsdb_trigger *trigger)
{
    struct ovsdb_jsonrpc_session *s, *ts;

    ts = CONTAINER_OF (trigger->session, struct ovsdb_jsonrpc_session, up);

    s = ovsdb_jsonrpc_sessions_find_session(sessions, ts);
    if (s) {
        struct ovsdb_jsonrpc_trigger *t;
        ovsdb_trigger_ref(trigger);
        t = CONTAINER_OF(trigger, struct ovsdb_jsonrpc_trigger, trigger);
        ovsdb_jsonrpc_trigger_complete(t);
    }
}


/* Jsonrpc front end monitor. */
struct ovsdb_jsonrpc_monitor {
    struct ovsdb_jsonrpc_session *session;
    struct ovsdb *db;
    struct hmap_node node;      /* In ovsdb_jsonrpc_session's "monitors". */
    struct json *monitor_id;
    struct ovsdb_monitor *dbmon;
    uint64_t unflushed;         /* The first transaction that has not been
                                       flushed to the jsonrpc remote client. */
    enum ovsdb_monitor_version version;
    struct ovs_refcount refcount;
};


void
ovsdb_jsonrpc_monitor_server_add(struct ovsdb_jsonrpc_monitor *m)
{
    struct ovsdb_monitor *dbmon;
    struct ovsdb_ipc *ipc;

    dbmon = ovsdb_monitor_add(m->dbmon);
    if (dbmon != m->dbmon) {
        /* Reuse existing dbmon. */
        ovsdb_monitor_remove_jsonrpc_monitor(m->dbmon, m, m->unflushed);
        ovsdb_monitor_add_jsonrpc_monitor(dbmon, m);
        free(m->dbmon);
        m->dbmon = dbmon;
    }

    /* Let sesssion add the monitor.  */
    ipc = ovsdb_ipc_monitor_create(OVSDB_IPC_MONITOR_SESSION_ADD, m);
    ovsdb_ipc_sendto(m->session->handler, ipc);
}

void
ovsdb_jsonrpc_monitor_session_add(struct ovs_list *sessions,
                                  struct ovsdb_jsonrpc_monitor *m)
{
    struct ovsdb_jsonrpc_session *s;

    s = ovsdb_jsonrpc_sessions_find_session(sessions, m->session);
    if (s) {
        ovs_assert(m == ovsdb_jsonrpc_monitor_find(s, m->monitor_id));
        ovsdb_jsonrpc_monitor_ref(m);
        hmap_insert(&s->monitors, &m->node, json_hash(m->monitor_id, 0));
    }
}

void
ovsdb_jsonrpc_monitor_server_remove(struct ovsdb_jsonrpc_monitor *m)
{
    ovsdb_monitor_remove_jsonrpc_monitor(m->dbmon, m, m->unflushed);
    ovsdb_jsonrpc_monitor_unref(m);
}

/* Implementation for "OVSDB_IPC_MONITOR_SESSION_REMOVE". */
void
ovsdb_jsonrpc_monitor_session_remove(struct ovs_list *sessions,
    struct ovsdb_jsonrpc_monitor *m)
{
    struct ovsdb_jsonrpc_session *s;

    s = ovsdb_jsonrpc_sessions_find_session(sessions, m->session);
    /* Skip the message if the session has been deleted in the meantime. */
    if (s) {
        if (m != ovsdb_jsonrpc_monitor_find(s, m->monitor_id)) {
            /* Make sure the monitor has not been deleted by the
             * session. */
            return ;
        }
        hmap_remove(&m->session->monitors, &m->node);
        ovsdb_jsonrpc_monitor_unref(m);
    }
}

struct ovsdb_jsonrpc_monitor *
ovsdb_jsonrpc_monitor_ref(const struct ovsdb_jsonrpc_monitor *monitor_)
{
    struct ovsdb_jsonrpc_monitor *monitor;

    monitor = CONST_CAST(struct ovsdb_jsonrpc_monitor *, monitor_);

    if (monitor) {
        ovs_refcount_ref(&monitor->refcount);
        ovsdb_jsonrpc_session_ref(monitor->session);
    }

    return monitor;
}

void
ovsdb_jsonrpc_monitor_unref(const struct ovsdb_jsonrpc_monitor * monitor_)
{
    struct ovsdb_jsonrpc_monitor *monitor;

    monitor = CONST_CAST(struct ovsdb_jsonrpc_monitor *, monitor_);

    if (monitor) {
        ovsdb_jsonrpc_session_unref(monitor->session);
        if (ovs_refcount_unref(&monitor->refcount) == 1) {
            free(monitor);
        }
    }
}

static struct ovsdb_jsonrpc_monitor *
ovsdb_jsonrpc_monitor_find(struct ovsdb_jsonrpc_session *s,
                           const struct json *monitor_id)
{
    struct ovsdb_jsonrpc_monitor *m;

    HMAP_FOR_EACH_WITH_HASH (m, node, json_hash(monitor_id, 0), &s->monitors) {
        if (json_equal(m->monitor_id, monitor_id)) {
            return m;
        }
    }

    return NULL;
}

static bool
parse_bool(struct ovsdb_parser *parser, const char *name, bool default_value)
{
    const struct json *json;

    json = ovsdb_parser_member(parser, name, OP_BOOLEAN | OP_OPTIONAL);
    return json ? json_boolean(json) : default_value;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_jsonrpc_parse_monitor_request(struct ovsdb_monitor *dbmon,
                                    const struct ovsdb_table *table,
                                    const struct json *monitor_request,
                                    size_t *allocated_columns)
{
    const struct ovsdb_table_schema *ts = table->schema;
    enum ovsdb_monitor_selection select;
    const struct json *columns, *select_json;
    struct ovsdb_parser parser;
    struct ovsdb_error *error;

    ovsdb_parser_init(&parser, monitor_request, "table %s", ts->name);
    columns = ovsdb_parser_member(&parser, "columns", OP_ARRAY | OP_OPTIONAL);
    select_json = ovsdb_parser_member(&parser, "select",
                                      OP_OBJECT | OP_OPTIONAL);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    if (select_json) {
        select = 0;
        ovsdb_parser_init(&parser, select_json, "table %s select", ts->name);
        if (parse_bool(&parser, "initial", true)) {
            select |= OJMS_INITIAL;
        }
        if (parse_bool(&parser, "insert", true)) {
            select |= OJMS_INSERT;
        }
        if (parse_bool(&parser, "delete", true)) {
            select |= OJMS_DELETE;
        }
        if (parse_bool(&parser, "modify", true)) {
            select |= OJMS_MODIFY;
        }
        error = ovsdb_parser_finish(&parser);
        if (error) {
            return error;
        }
    } else {
        select = OJMS_INITIAL | OJMS_INSERT | OJMS_DELETE | OJMS_MODIFY;
    }

    ovsdb_monitor_table_add_select(dbmon, table, select);
    if (columns) {
        size_t i;

        if (columns->type != JSON_ARRAY) {
            return ovsdb_syntax_error(columns, NULL,
                                      "array of column names expected");
        }

        for (i = 0; i < columns->u.array.n; i++) {
            const struct ovsdb_column *column;
            const char *s;

            if (columns->u.array.elems[i]->type != JSON_STRING) {
                return ovsdb_syntax_error(columns, NULL,
                                          "array of column names expected");
            }

            s = columns->u.array.elems[i]->u.string;
            column = shash_find_data(&table->schema->columns, s);
            if (!column) {
                return ovsdb_syntax_error(columns, NULL, "%s is not a valid "
                                          "column name", s);
            }
            ovsdb_monitor_add_column(dbmon, table, column, select,
                                     allocated_columns);
        }
    } else {
        struct shash_node *node;

        SHASH_FOR_EACH (node, &ts->columns) {
            const struct ovsdb_column *column = node->data;
            if (column->index != OVSDB_COL_UUID) {
                ovsdb_monitor_add_column(dbmon, table, column, select,
                                         allocated_columns);
            }
        }
    }

    return NULL;
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_monitor_create(struct ovsdb_jsonrpc_session *s, struct ovsdb *db,
                             struct json *params,
                             enum ovsdb_monitor_version version,
                             const struct json *request_id)
{
    struct ovsdb_jsonrpc_monitor *m = NULL;
    struct ovsdb_monitor *dbmon = NULL;
    struct json *monitor_id, *monitor_requests;
    struct ovsdb_error *error = NULL;
    struct shash_node *node;
    struct json *json;

    if (json_array(params)->n != 3) {
        error = ovsdb_syntax_error(params, NULL, "invalid parameters");
        goto error;
    }
    monitor_id = params->u.array.elems[1];
    monitor_requests = params->u.array.elems[2];
    if (monitor_requests->type != JSON_OBJECT) {
        error = ovsdb_syntax_error(monitor_requests, NULL,
                                   "monitor-requests must be object");
        goto error;
    }

    if (ovsdb_jsonrpc_monitor_find(s, monitor_id)) {
        error = ovsdb_syntax_error(monitor_id, NULL, "duplicate monitor ID");
        goto error;
    }

    m = xzalloc(sizeof *m);
    m->session = s;
    m->db = db;
    m->dbmon = ovsdb_monitor_create(db, m);
    m->unflushed = 0;
    m->version = version;
    hmap_insert(&s->monitors, &m->node, json_hash(monitor_id, 0));
    m->monitor_id = json_clone(monitor_id);

    SHASH_FOR_EACH (node, json_object(monitor_requests)) {
        const struct ovsdb_table *table;
        const char *column_name;
        size_t allocated_columns;
        const struct json *mr_value;
        size_t i;

        table = ovsdb_get_table(m->db, node->name);
        if (!table) {
            error = ovsdb_syntax_error(NULL, NULL,
                                       "no table named %s", node->name);
            goto error;
        }

        ovsdb_monitor_add_table(m->dbmon, table);

        /* Parse columns. */
        mr_value = node->data;
        allocated_columns = 0;
        if (mr_value->type == JSON_ARRAY) {
            const struct json_array *array = &mr_value->u.array;

            for (i = 0; i < array->n; i++) {
                error = ovsdb_jsonrpc_parse_monitor_request(
                    m->dbmon, table, array->elems[i], &allocated_columns);
                if (error) {
                    goto error;
                }
            }
        } else {
            error = ovsdb_jsonrpc_parse_monitor_request(
                m->dbmon, table, mr_value, &allocated_columns);
            if (error) {
                goto error;
            }
        }

        column_name = ovsdb_monitor_table_check_duplicates(m->dbmon, table);

        if (column_name) {
            error = ovsdb_syntax_error(mr_value, NULL, "column %s "
                                       "mentioned more than once",
                                        column_name);
            goto error;
        }
    }

    dbmon = ovsdb_monitor_add(m->dbmon);
    if (dbmon != m->dbmon) {
        /* Found an exisiting dbmon, reuse the current one. */
        ovsdb_monitor_remove_jsonrpc_monitor(m->dbmon, m, m->unflushed);
        ovsdb_monitor_add_jsonrpc_monitor(dbmon, m);
        m->dbmon = dbmon;
    }

    ovsdb_monitor_get_initial(m->dbmon);
    json = ovsdb_jsonrpc_monitor_compose_update(m, true);
    json = json ? json : json_object_create();
    return jsonrpc_create_reply(json, request_id);

error:
    if (m) {
        ovsdb_jsonrpc_monitor_destroy(m);
    }

    json = ovsdb_error_to_json(error);
    ovsdb_error_destroy(error);
    return jsonrpc_create_error(json, request_id);
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_monitor_cancel(struct ovsdb_jsonrpc_session *s,
                             struct json_array *params,
                             const struct json *request_id)
{
    if (params->n != 1) {
        return jsonrpc_create_error(json_string_create("invalid parameters"),
                                    request_id);
    } else {
        struct ovsdb_jsonrpc_monitor *m;

        m = ovsdb_jsonrpc_monitor_find(s, params->elems[0]);
        if (!m) {
            return jsonrpc_create_error(json_string_create("unknown monitor"),
                                        request_id);
        } else {
            ovsdb_jsonrpc_monitor_destroy(m);
            return jsonrpc_create_reply(json_object_create(), request_id);
        }
    }
}

static void
ovsdb_jsonrpc_monitor_remove_all(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_monitor *m, *next;

    HMAP_FOR_EACH_SAFE (m, next, node, &s->monitors) {
        ovsdb_jsonrpc_monitor_destroy(m);
    }
}

static struct json *
ovsdb_jsonrpc_monitor_compose_update(struct ovsdb_jsonrpc_monitor *m,
                                     bool initial)
{
    if (!ovsdb_monitor_needs_flush(m->dbmon, m->unflushed)) {
        return NULL;
    }

    return ovsdb_monitor_get_update(m->dbmon, initial, &m->unflushed,
                                    m->version);
}

static bool
ovsdb_jsonrpc_monitor_needs_flush(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_monitor *m;

    HMAP_FOR_EACH (m, node, &s->monitors) {
        if (ovsdb_monitor_needs_flush(m->dbmon, m->unflushed)) {
            return true;
        }
    }

    return false;
}

void
ovsdb_jsonrpc_monitor_destroy(struct ovsdb_jsonrpc_monitor *m)
{
    json_destroy(m->monitor_id);
    hmap_remove(&m->session->monitors, &m->node);
    ovsdb_monitor_remove_jsonrpc_monitor(m->dbmon, m, m->unflushed);
    free(m);
}

static struct jsonrpc_msg *
ovsdb_jsonrpc_create_notify(const struct ovsdb_jsonrpc_monitor *m,
                            struct json *params)
{
    const char *method;

    switch(m->version) {
    case OVSDB_MONITOR_V1:
        method = "update";
        break;
    case OVSDB_MONITOR_V2:
        method = "update2";
        break;
    case OVSDB_MONITOR_VERSION_MAX:
    default:
        OVS_NOT_REACHED();
    }

    return jsonrpc_create_notify(method, params);
}

static void
ovsdb_jsonrpc_monitor_flush_all(struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_monitor *m;

    HMAP_FOR_EACH (m, node, &s->monitors) {
        struct json *json;

        json = ovsdb_jsonrpc_monitor_compose_update(m, false);
        if (json) {
            struct jsonrpc_msg *msg;
            struct json *params;

            params = json_array_create_2(json_clone(m->monitor_id), json);
            msg = ovsdb_jsonrpc_create_notify(m, params);
            jsonrpc_session_send(s->js, msg);
        }
    }
}

void
ovsdb_jsonrpc_disable_monitor2(void)
{
    /* Once disabled, it is not possible to re-enable it. */
    monitor2_enable__ = false;
}

void
ovsdb_jsonrpc_sessions_run(struct ovs_list *sessions)
{
    struct ovsdb_jsonrpc_session *s, *next;

    LIST_FOR_EACH_SAFE (s, next, node, sessions) {
        int error = ovsdb_jsonrpc_session_run(s);
        if (error) {
            ovsdb_jsonrpc_session_close(s);
        }
    }
}

void
ovsdb_jsonrpc_sessions_wait(struct ovs_list *sessions)
{
    struct ovsdb_jsonrpc_session *s;

    LIST_FOR_EACH (s, node, sessions) {
        ovsdb_jsonrpc_session_wait(s);
    }
}

void
ovsdb_jsonrpc_sessions_close(struct ovs_list *sessions,
                             const struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s, *next;

    LIST_FOR_EACH_SAFE (s, next, node, sessions) {
        if (s->remote == remote) {
            ovsdb_jsonrpc_session_close(s);
        }
    }
}

/* Forces all of the JSON-RPC sessions for the given 'remote' to
 * disconnect and reconnect. */
void
ovsdb_jsonrpc_sessions_reconnect(struct ovs_list *sessions,
                                 const struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s, *next;

    LIST_FOR_EACH_SAFE (s, next, node, sessions) {
        if (s->remote == remote) {
            jsonrpc_session_force_reconnect(s->js);
            if (!jsonrpc_session_is_alive(s->js)) {
                ovsdb_jsonrpc_session_close(s);
            }
        }
    }
}

size_t
ovsdb_jsonrpc_sessions_count(const struct ovs_list *sessions,
                             const struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s = NULL;
    size_t count = 0;

    LIST_FOR_EACH (s, node, sessions) {
        if (s->remote == remote) {
            count++;
        }
    }
    return count;
}

/* Sets the options for all of the JSON-RPC sessions managed by 'remote' to
 * 'options'.
 *
 * (The DSCP value can't be changed directly; the caller must instead close and
 * re-open the session.) */
void
ovsdb_jsonrpc_sessions_set_options(struct ovs_list *sessions,
                                   const struct ovsdb_jsonrpc_remote *remote,
                                   const struct ovsdb_jsonrpc_options *options)
{
    struct ovsdb_jsonrpc_session *s;

    LIST_FOR_EACH (s, node, sessions) {
        if (s->remote == remote) {
            ovsdb_jsonrpc_session_set_options(s, options);
        }
    }
}

/* Return the first session held in 'sessions' for the 'remote'. */
struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_sessions_first(const struct ovs_list *sessions,
                             const struct ovsdb_jsonrpc_remote *remote)
{
    struct ovsdb_jsonrpc_session *s;

    LIST_FOR_EACH (s, node, sessions) {
        if (s->remote == remote) {
            return s;
        }
    }

    return NULL;
}

void
ovsdb_jsonrpc_sessions_get_memory_usage(const struct ovs_list *sessions,
                                        struct simap *usage)
{
    struct ovsdb_jsonrpc_session *s;

    LIST_FOR_EACH (s, node, sessions) {
        ovsdb_jsonrpc_session_get_memory_usage(s, usage);
    }
}

struct sessions_handler *
ovsdb_jsonrpc_session_handler(struct ovsdb_session *session)
{
    struct ovsdb_jsonrpc_session *s;

    s = CONTAINER_OF(session, struct ovsdb_jsonrpc_session, up);

    return s->handler;
}

bool
ovsdb_jsonrpc_session_handled_locally(struct ovsdb_jsonrpc_session *s)
{
    return s->handler == *thread_handler_get();
}

void
ovsdb_jsonrpc_sessions_add(struct ovs_list *sessions,
                           struct ovsdb_jsonrpc_session *s)
{
    ovs_list_push_back(sessions, &s->node);
}

struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_sessions_find_session(const struct ovs_list *sessions,
                                    const struct ovsdb_jsonrpc_session *s)
{
    struct ovsdb_jsonrpc_session *js;

    LIST_FOR_EACH (js, node, sessions) {
        if (s == js) {
            return js;
        }
    }

    return NULL;
}

struct ovsdb_jsonrpc_session *
ovsdb_jsonrpc_session_ref(const struct ovsdb_jsonrpc_session *session_)
{
    struct ovsdb_jsonrpc_session *session;

    session = CONST_CAST(struct ovsdb_jsonrpc_session *, session_);
    if (session) {
        ovs_refcount_ref(&session->refcount);
    }
    return session;
}

void
ovsdb_jsonrpc_session_unref(const struct ovsdb_jsonrpc_session *session_)
{
    struct ovsdb_jsonrpc_session *session;

    session = CONST_CAST(struct ovsdb_jsonrpc_session *, session_);
    if (session && ovs_refcount_unref(&session->refcount) == 1) {
        free(session);
    }
}
