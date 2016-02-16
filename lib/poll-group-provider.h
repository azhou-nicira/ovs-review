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
/*
 * Poll group: An application aware poll interface
 *
 * Poll group implements a higher level interface than those offered by
 * poll loop and aims to improve efficiency with high number concurrent
 * connections.
 *
 * Poll group sits between the application and the stream layer. Same kind
 * of application sessions can ask their individual streams to join
 * a common poll group, which is created by the application.
 * In addition, the application session is required to provide an
 * unique pointer that is only associated with the session, called
 * 'caller_event' when joining a poll group. Each poll group then
 * in term registers with the main poll loop.
 *
 * When poll_block() wakes up, each poll group delivers only a set of
 * 'caller_event's that correspond to the sessions that are responsible
 * for poll_block waken up.  Thus, the main loop can avoid interrogate all
 * sessions which is required when using poll loop directly.
 *
 * On Linux, poll group maps well into the epoll(7) facility. Each
 * poll group creates an file descriptor that is created with epoll_create(2)
 * system call. Epoll implementation provides additional performance
 * benefits by aggregate multiple system calls into a single one.
 *
 * Poll group is designed to be closely integrated with the stream class.
 * An newly created application session can join a poll group at any time
 * during its life cycle. Internally, a stream only turns on 'poll group'
 * when a stream is fully connected.  Stream connection set up and tear down
 * is still managed by the poll loop, but those mode switches are managed
 * internally with the stream class, transparent to the application.
 *
 * An application session can always leave poll group at any time, or
 * simply never join one. In both cases, the stream will fall back to
 * use poll loop directly.
 */

struct poll_group_class {
    /* Prefix of a poll group name, e.g. "default", "epoll" . */
    const char *name;

    /* The following APIs are required to be implemented in any
     * class.
     */

    /* Create a new poll group. */
    struct poll_group *(*create)(const char *name);

    /* Shut down a poll group, release memory and other resources. */
    void (*close)(struct poll_group *group);

    /* 'join' allows a new 'fd' to join a poll group. 'caller_event' are user
     * provided pointer that is opaque to poll group. Those pointers
     * are passed back to the user when poll_group_get_events() are
     * called. */
    int (*join)(struct poll_group *group, int fd, void *caller_event);

    /* 'updates' allows application to inform whether the 'fd' is
     * interested to be waken up when 'fd' is ready for transmission.
     */
    int (*update)(struct poll_group *group, int fd, bool write,
                  void *caller_event);

    /* 'leave' is the opposite of 'join'. 'fd' will no longer be watched
     * by poll group. */
    int (*leave)(struct poll_group *group, int fd);

    /* 'poll_wait' is poll group's interface to poll loop, so that the
     * poll group itself can be waken up by poll loop. */
    void (*poll_wait)(struct poll_group *group);

    /* The following APIs are optional and can be NULL. */

    /* 'get_events', if implemented is used for an implementation to fill
     * up the poll_group's 'events' buffer, using poll_group_notify().
     * It will be invoked when poll_group_get_events() is called. */
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
    size_t n_joined;    /* Total number of joined streams.  */


    /* Data storage provide for implementing poll_group_get_events().
     * The size of **events buffer will be managed such that its size can
     * accommodate at least up to 'n_events' of void pointer array.
     *
     * The events are filled by 'poll_group_notify()', in sequential order.
     * 'n_events' are used to track the number of events added by
     * poll_group_notify().
     *
     * 'poll_group_get_events()' allows caller to retrieve the 'events'
     * array and 'n_evnets' stored. However, this call in one short; it
     * resets 'n_events'. The next poll_group_notify() call will start
     * to add 'caller_event' into an empty array.
     */
    void **events;       /* Events buffer array, stores 'call_events'
                            pointers user provided to poll_group_join() */
    size_t n_events;     /* Number of events received from
                            poll_group_notify() so far, but has not been
                            retrieved by poll_group_get_events() yet.  */
    size_t n_allocated;  /* Used internally for x2nrealloc().   */
};

static inline void
poll_group_assert_class(const struct poll_group *group,
                        const struct poll_group_class *class)
{
    ovs_assert(group->class == class);
}

void poll_group_init(struct poll_group *, const char *name,
                     const struct poll_group_class *);

extern const struct poll_group_class epoll_group_class;

#endif /* poll-group-provider.h */
