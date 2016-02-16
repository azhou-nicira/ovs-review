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

#ifndef POLL_GROUP_PROVIDER_H
#define POLL_GROUP_PROVIDER_H 1

#include <stdbool.h>
#include <sys/types.h>
#include "util.h"

struct poll_group;

struct poll_group_class {
    const char *name;    /* name of the class. */
    /* The following APIs are required to be implemented in any
     * class.
     */
    struct poll_group *(*create)(const char *name);
    void (*close)(struct poll_group *group);

    int (*join)(struct poll_group *group, int fd, void *caller_event);
    int (*update)(struct poll_group *group, int fd, bool write);
    int (*leave)(struct poll_group *group, int fd);

    /* Ask poll_loop() to wait for all joined 'fd's */
    /* optional API */
    void (*poll_wait)(struct poll_group *group);
    void (*get_events)(struct poll_group *group);
};

static inline bool
poll_group_class_is_valid(const struct poll_group_class *class)
{
    return (class->name && class->create && class->close
            && class->join && class->update && class->leave 
            && class->poll_wait);
}

/* poll_group.
 *
 * This structure should be treated as opaque by implementation. */
struct poll_group {
    const struct poll_group_class *class;
    char *name;         /* Name of the poll group, useful for logging. */
    size_t n_joined;    /* Total number of joined objs.  */

    /* Per poll block() events. */
    void **events;       /* events buffer.  */
    size_t n_events;     /* Number of events received for a poll_block(),
                         but has not read by the user.
                         This is a one short counter; get_events()
                         should clear this counter.  */
    size_t n_allocated;  /* Size of memory allocated for 'events'. */
};

static inline void
poll_group_assert_class(const struct poll_group *group,
                        const struct poll_group_class *class)
{
    ovs_assert(group->class == class);
}

void poll_group_init(struct poll_group *, const char *name,
                     const struct poll_group_class *);

extern const struct poll_group_class poll_group_default_class;
#ifdef __linux__
extern const struct poll_group_class poll_group_epoll_class;
#endif


extern const struct poll_group_class poll_group_default_class;

#endif /* poll-group-provider.h */
