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
#include <sys/epoll.h>
#include <stdlib.h>
#include <unistd.h>
#include "openvswitch/vlog.h"
#include "hash.h"
#include "hmap.h"
#include "poll-group.h"
#include "poll-group-provider.h"
#include "poll-loop.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(epoll_group);


struct epoll_group;
struct fd_node {
    struct hmap_node hmap_node;
    int fd;
    struct stream *stream;    /* Stream associated with the fd */
    struct poll_group *poll_group;

    /* events that was last set using epoll_ctl(), called from
     * epoll_group_get_events().   */
    struct epoll_event current;

    /* epoll_group_join() call will initially create this node,
     * the event.data.ptr will be set to 'caller_event'. This
     * value can not be changed for the life of this node.
     *
     * The initial value of event.events will be set to EPOLLIN.
     * It can be changed to EPOLLIN | EPOLLOUT if epoll_group_update()
     * is called with 'write' set to true. There is no way to
     * remove EPOLLIN flags.
     *
     * epoll_group_update() can be called multiple times to update the
     * same node. The union of all updates will take effect when
     * when epoll_group_get_events() is called.  If applied,
     * the 'current' will also be update to reflect the new setting,
     * while 'event' will be reset to the creation state, ready to
     * accumulate the next batch of epoll_group_update() calls.
     */
    struct epoll_event event;
};

static struct fd_node *find_fd_node(struct epoll_group *, int fd);
static struct fd_node *create_fd_node(struct epoll_group *, int, void *);
static void find_and_delete_fd_node_assert(struct epoll_group *, int fd);

struct epoll_group {
    struct poll_group up;
    int epoll_fd;

    /* Maintain a buffer used for epoll_wait() call */
    struct epoll_event *epoll_events;
    size_t n_allocated;

    /* Stores fds that have joined. */
    struct hmap fd_nodes;
};


static struct epoll_group *
epoll_group_cast(struct poll_group *group)
{
    poll_group_assert_class(group, &epoll_group_class);
    return CONTAINER_OF(group, struct epoll_group, up);
}

static struct poll_group *
epoll_group_create(const char *name)
{
    int epoll_fd = epoll_create(10);

    if (epoll_fd == -1) {
        VLOG_ERR("epoll_create: %s", ovs_strerror(errno));
        return NULL;
    }

    struct epoll_group *group;
    group = xmalloc(sizeof *group);
    poll_group_init(&group->up, name, &epoll_group_class);

    group->epoll_fd = epoll_fd;
    group->epoll_events = NULL;
    group->n_allocated = 0;

    hmap_init(&group->fd_nodes);
    return &group->up;
}

static void
epoll_group_close(struct poll_group *group_)
{
    struct epoll_group *group = epoll_group_cast(group_);
    int retval;

    retval = close(group->epoll_fd);
    if (retval == -1) {
        VLOG_ERR("close: %s", ovs_strerror(errno));
    }
    free(group->epoll_events);

    hmap_destroy(&group->fd_nodes);
}

static int
epoll_group_join(struct poll_group *group_, int fd, void *caller_event)
{
    struct epoll_group *group = epoll_group_cast(group_);
    size_t n_joined = group_->n_joined;
    struct fd_node *node;
    int retval;

    ovs_assert(!find_fd_node(group, fd));
    node = create_fd_node(group, fd, caller_event);

    retval = epoll_ctl(group->epoll_fd, EPOLL_CTL_ADD, fd, &node->current);
    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_ADD): %s", ovs_strerror(errno));
        retval = errno;
    } else {
        /* Increase the epoll_wait() receiver buffer if necessary to
         * accommodate the newly joined 'fd'. */
        if (n_joined + 1 >= group->n_allocated) {
           struct epoll_event *epoll_events = group->epoll_events;

           epoll_events = x2nrealloc(epoll_events, &group->n_allocated,
                                     sizeof(*epoll_events));

           group->epoll_events = epoll_events;
       }
    }

    return retval;
}

static int
epoll_group_leave(struct poll_group *group_, int fd)
{
    struct epoll_group *group = epoll_group_cast(group_);
    int retval;

    find_and_delete_fd_node_assert(group, fd);
    retval = epoll_ctl(group->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_DEL): %s", ovs_strerror(errno));
        retval = errno;
    }

    return retval;
}
/* Use epoll_ctl() syscall to update fd's events to match with
 * node->events, also update node->current and reset node->events. */
static int
epoll_group_modify_fd__(struct epoll_group *group, struct fd_node *node)
{
    struct epoll_event *e = &node->current;
    int retval = epoll_ctl(group->epoll_fd, EPOLL_CTL_MOD, node->fd, e);
    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_MOD): %s", ovs_strerror(errno));
        retval = errno;
    }

    return retval;
}

static int
epoll_group_modify_fd(struct epoll_group *group, struct fd_node *node)
{
    int retval = 0;

    /* Check to see if a syscall can be avoided.  */
    if (node->event.events != node->current.events) {
        node->current.events = node->event.events;
        retval = epoll_group_modify_fd__(group, node);
    }
    return retval;
}

static int
epoll_group_update(struct poll_group *group_, int fd, bool write,
                        void *caller_event)
{
    struct epoll_group *group = epoll_group_cast(group_);
    struct fd_node *node;

    node = find_fd_node(group, fd);
    ovs_assert(node && node->event.data.ptr == caller_event);
    node->event.events |= (write ? EPOLLOUT : 0);

    if (write) {
       /* For write updates, issue epoll_ctl() as soon as possible.
        * Otherwise, poll_block() may not wake up on epoll_fd. */
       epoll_group_modify_fd(group, node);
    }

    return 0;
}

static void
epoll_group_poll_wait(struct poll_group *group_)
{
    struct epoll_group *group = epoll_group_cast(group_);
    size_t n_joined = group_->n_joined;

    if (n_joined) {
        poll_fd_wait(group->epoll_fd, POLLIN);
    }
}


static void
epoll_group_get_events(struct poll_group *group_)
{
    struct epoll_group *group = epoll_group_cast(group_);
    size_t n_joined = group_->n_joined;

    if (n_joined) {
        struct fd_node *fd_node;

        /* Update fd's events before calling epoll_wait */
        HMAP_FOR_EACH (fd_node, hmap_node, &group->fd_nodes) {
            epoll_group_modify_fd(group, fd_node);

            /* Restore events for the next interval. */
           fd_node->event.events = EPOLLIN;
        };

        int retval = epoll_wait(group->epoll_fd, group->epoll_events,
                                n_joined, 0);

        if (retval == -1) {
            VLOG_ERR("epoll_wait: %s", ovs_strerror(errno));
            retval = errno;
        } else {
            /* Deliver the caller events to the poll_group */
            int i;
            for (i = 0; i < retval; i ++)  {
                struct epoll_event *event = &group->epoll_events[i];
                poll_group_notify(group_, event->data.ptr);
            }
        }
    }
}


/* Look up the fd node within fd_nodes. */
static struct fd_node *
find_fd_node(struct epoll_group *group, int fd)
{
    struct fd_node *node;
    HMAP_FOR_EACH_WITH_HASH (node, hmap_node,
                             hash_int(fd, 0),
                             &group->fd_nodes) {
        if (node->fd == fd) {
            return node;
        }
    }
    return NULL;
}

static struct fd_node *
create_fd_node(struct epoll_group *group, int fd, void *caller_event)
{
    struct fd_node *node;

    node = xmalloc(sizeof *node);
    hmap_insert(&group->fd_nodes, &node->hmap_node, hash_int(fd, 0));
    node->fd = fd;

    node->event.events = EPOLLIN;
    node->event.data.ptr = caller_event;

    node->current.events = EPOLLIN;
    node->current.data.ptr = caller_event;

    return node;
}

static void
find_and_delete_fd_node_assert(struct epoll_group *group, int fd)
{
    struct fd_node *node;

    node = find_fd_node(group, fd);
    ovs_assert(node);
    hmap_remove(&group->fd_nodes, &node->hmap_node);
    free(node);
}


const struct poll_group_class epoll_group_class = {
     "epoll",                 /* name */
     epoll_group_create,      /* create */
     epoll_group_close,       /* close */

     epoll_group_join,        /* join */
     epoll_group_update,      /* update */
     epoll_group_leave,       /* leave */

     epoll_group_poll_wait,   /* poll wait */
     epoll_group_get_events   /* get events */
};
