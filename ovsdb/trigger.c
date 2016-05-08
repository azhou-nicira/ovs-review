/* Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include "trigger.h"

#include <limits.h>

#include "json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "poll-loop.h"
#include "server.h"

static bool ovsdb_trigger_try(struct ovsdb_trigger *, long long int now,
                              struct ovs_list *completed);
static void ovsdb_trigger_complete(struct ovsdb_trigger * t,
                                   struct ovs_list *completed);

void
ovsdb_trigger_init(struct ovsdb_session *session, struct ovsdb *db,
                   struct ovsdb_trigger *trigger,
                   struct json *request, long long int now)
{
    trigger->session = session;
    trigger->db = db;
    trigger->request = request;
    trigger->result = NULL;
    trigger->created = now;
    trigger->timeout_msec = LLONG_MAX;
    trigger->result = NULL;
    ovs_list_init(&trigger->node);
    ovs_refcount_init(&trigger->refcount);
}

void
ovsdb_trigger_server_add(struct ovsdb_trigger *trigger)
{
   ovsdb_trigger_ref(trigger);
   ovs_list_push_back(&trigger->db->triggers, &trigger->node);
   trigger->db->run_triggers = true;
}

void
ovsdb_trigger_server_remove(struct ovsdb_trigger *trigger)
{
   ovs_list_remove(&trigger->node);
   ovsdb_trigger_unref(trigger);
}

static void
ovsdb_trigger_destroy(struct ovsdb_trigger *trigger)
{
    ovs_list_remove(&trigger->node);
    json_destroy(trigger->request);
    json_destroy(trigger->result);
}

bool
ovsdb_trigger_is_complete(const struct ovsdb_trigger *trigger)
{
    return trigger->result != NULL;
}

struct json *
ovsdb_trigger_steal_result(struct ovsdb_trigger *trigger)
{
    struct json *result = trigger->result;
    trigger->result = NULL;
    return result;
}

void
ovsdb_trigger_server_run(struct ovsdb *db, long long int now,
                  struct ovs_list *completed)
{
    struct ovsdb_trigger *t, *next;
    bool run_triggers;

    run_triggers = db->run_triggers;
    db->run_triggers = false;
    LIST_FOR_EACH_SAFE (t, next, node, &db->triggers) {
        if (run_triggers || now - t->created >= t->timeout_msec) {
            ovsdb_trigger_try(t, now, completed);
        }
    }
}

void
ovsdb_trigger_server_wait(struct ovsdb *db, long long int now)
{
    if (db->run_triggers) {
        poll_immediate_wake();
    } else {
        long long int deadline = LLONG_MAX;
        struct ovsdb_trigger *t;

        LIST_FOR_EACH (t, node, &db->triggers) {
            if (t->created < LLONG_MAX - t->timeout_msec) {
                long long int t_deadline = t->created + t->timeout_msec;
                if (deadline > t_deadline) {
                    deadline = t_deadline;
                    if (now >= deadline) {
                        break;
                    }
                }
            }
        }

        if (deadline < LLONG_MAX) {
            poll_timer_wait_until(deadline);
        }
    }
}

static bool
ovsdb_trigger_try(struct ovsdb_trigger *t, long long int now,
                  struct ovs_list *completed)
{
    t->result = ovsdb_execute(t->db, t->session,
                              t->request, now - t->created, &t->timeout_msec);
    if (t->result) {
        ovsdb_trigger_complete(t, completed);
        return true;
    } else {
        return false;
    }
}

static void
ovsdb_trigger_complete(struct ovsdb_trigger *t, struct ovs_list *completed)
{
    ovs_assert(t->result != NULL);
    ovs_list_remove(&t->node);
    ovs_list_push_back(completed, &t->node);
}

struct ovsdb_trigger *
ovsdb_trigger_ref(const struct ovsdb_trigger *trigger_)
{
    struct ovsdb_trigger *trigger;

    trigger = CONST_CAST(struct ovsdb_trigger *, trigger_);
    if (trigger) {
        ovs_refcount_ref(&trigger->refcount);
    }
    return trigger;
}

void
ovsdb_trigger_unref(const struct ovsdb_trigger *trigger_)
{
    struct ovsdb_trigger *trigger;

    trigger = CONST_CAST(struct ovsdb_trigger *, trigger_);
    if (trigger && ovs_refcount_unref(&trigger->refcount) == 1) {
        ovsdb_trigger_destroy(trigger);
        free(trigger);
    }
}
