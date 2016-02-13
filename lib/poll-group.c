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

#include <config.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "dynamic-string.h"
#include "poll-loop.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "poll-group.h"
#include "poll-group-provider.h"

VLOG_DEFINE_THIS_MODULE(poll_group);

/* Helper functions */
static void add_caller_event(struct poll_group *group, void *caller_event);


static const struct poll_group_class *
poll_group_select_class(const char *class_name OVS_UNUSED, size_t len OVS_UNUSED)
{
    /* Nothing has being impemented yet. */
    return NULL;
}

static int
poll_group_is_valid(struct poll_group *group)
{
     const struct poll_group_class *class;
     if (!group) {
         return PG_ERROR_NO_GROUP;
     }

     class = group->class;
     if (!class) {
         return PG_ERROR_NO_CLASS;
     }

     if (!poll_group_class_is_valid(class)) {
         return PG_ERROR_INVALID_CLASS;
     }

    return 0;
}


void
poll_group_init(struct poll_group *group,
                const char *name,
                const struct poll_group_class *class)
{
    group->name = xstrdup(name);
    group->class = class;
    group->n_joined = 0;

    group->events = NULL;
    group->n_events = 0;
    group->n_allocated = 0;
}

struct poll_group *
poll_group_create(const char *name)
{
    const struct poll_group_class *class;
    size_t prefix_len;
    const char *group_name;
    struct poll_group *group = NULL;


    prefix_len = strcspn(name, ":");
    if (name[prefix_len] == '\0') {
        class = poll_group_select_class("", 0);
        group_name = name;
    } else {
        class = poll_group_select_class(name, prefix_len);
        group_name = &name[prefix_len + 1];
    }

    if (poll_group_class_is_valid(class)) {
        group = class->create(group_name);
    }

    return group;
}

void
poll_group_close(struct poll_group *group)
{
    int ret = poll_group_is_valid(group);

    if (ret) {
        group->class->close(group);
        group->n_allocated = 0;
        group->n_allocated = 0;
        group->n_joined = 0;

        free(group->events);
        group->events = NULL;
        free(group->name);
        group->name = NULL;
    }

    free(group);
}

int
poll_group_join(struct poll_group *group, int fd, void *caller_event)
{
    int ret = poll_group_is_valid(group);

    if (!ret) {
        ret = group->class->join(group, fd, caller_event);
        if (!ret) {
            group->n_joined++;
        }
    }

    return ret;
}

int
poll_group_update(struct poll_group *group, int fd, bool write)
{
    int ret = poll_group_is_valid(group);

    if (!ret) {
        ret = group->class->update(group, fd, write);
    }

    return ret;
}

int
poll_group_leave(struct poll_group *group, int fd)
{
    int ret = poll_group_is_valid(group);

    if (!ret) {
        ret = group->class->leave(group, fd);
        if (!ret) {
            group->n_joined--;
        }
    }

    return ret;
}

void
poll_group_poll_wait(struct poll_group *group)
{
    int ret = poll_group_is_valid(group);

    if (!ret) {
        group->n_events = 0;
        group->class->poll_wait(group);
    }
}

void
poll_group_notify(struct poll_group *group, void *caller_event)
{
    if (group && caller_event) {
        add_caller_event(group, caller_event);
    }
}

void
poll_group_get_events(struct poll_group *group, void **caller_event,
                      size_t *n)
{
    if (group && group->class->get_events) {
            group->class->get_events(group);
    }
    *n = group->n_events;
    *caller_event = &group->events;
}


static void
add_caller_event(struct poll_group *group, void *caller_event)
{
     size_t n_events = group->n_events;
     size_t n_allocated = group->n_allocated;

     if (n_events >= n_allocated) {
         void **events = group->events;
         events = x2nrealloc(events, &group->n_allocated, sizeof events[0]);
         group->events = events;
     }

     group->events[group->n_events++] = caller_event;

}
