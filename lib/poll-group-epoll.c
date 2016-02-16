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
#include "poll-group.h"
#include "poll-group-provider.h"
#include "poll-loop.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(poll_group_epoll);


struct poll_group_epoll {
    struct poll_group up;
    int epoll_fd;

    /* Maintain a buffer used for epoll_wait() call */
    struct epoll_event *events;
    size_t n_allocated;
};


static struct poll_group_epoll *
poll_group_epoll_cast(struct poll_group *group)
{
    poll_group_assert_class(group, &poll_group_epoll_class);
    return CONTAINER_OF(group, struct poll_group_epoll, up);
}

static struct poll_group *
poll_group_epoll_create(const char *name)
{
    int epoll_fd = epoll_create(10);

    if (epoll_fd == -1) {
        VLOG_ERR("epoll_create: %s", ovs_strerror(errno));
        return NULL;
    }

    struct poll_group_epoll *group;
    group = xmalloc(sizeof *group);
    poll_group_init(&group->up, name, &poll_group_epoll_class);

    group->events = NULL;
    group->n_allocated = 0;
    return &group->up;
}

static void
poll_group_epoll_close(struct poll_group *group_)
{
    struct poll_group_epoll *group = poll_group_epoll_cast(group_);
    int retval;

    retval = close(group->epoll_fd);
    if (retval == -1) {
        VLOG_ERR("close: %s", ovs_strerror(errno));
    }
    free(group->events);
}

static int
poll_group_epoll_join(struct poll_group *group_, int fd, void *caller_event)
{
    struct poll_group_epoll *group = poll_group_epoll_cast(group_);
    size_t n_joined = group_->n_joined;
    struct epoll_event e;
    int retval;

    e.events = EPOLLIN,
    e.data.ptr = caller_event,

    retval = epoll_ctl(group->epoll_fd, EPOLL_CTL_ADD, fd, &e);

    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_ADD: %s", ovs_strerror(errno));
        retval = errno;
    } else {
        /* Increase the epoll_wait() receiver buffer if ncessary. */

       if (n_joined >= group->n_allocated) {
            x2nrealloc(group->events, &group->n_allocated, sizeof(e));
       }
    }

    return retval;
}

static int
poll_group_epoll_leave(struct poll_group *group_, int fd)
{
    struct poll_group_epoll *group = poll_group_epoll_cast(group_);
    int retval;

    retval = epoll_ctl(group->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_DEL): %s", ovs_strerror(errno));
        retval = errno;
    }

    return retval;
}

static int
poll_group_epoll_update(struct poll_group *group_, int fd, bool write) 
{
    struct poll_group_epoll *group = poll_group_epoll_cast(group_);
    struct epoll_event e;
    int retval;

    e.events = EPOLLIN | (write ? EPOLLOUT : 0);
    //e.data.ptr = caller_event;
    e.data.ptr = NULL;

    retval = epoll_ctl(group->epoll_fd, EPOLL_CTL_MOD, fd, &e);
    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_MOD): %s", ovs_strerror(errno));
        retval = errno;
    }

    return retval;
}

static void
poll_group_epoll_poll_wait(struct poll_group *group_)
{
    struct poll_group_epoll *group = poll_group_epoll_cast(group_);

    poll_fd_wait(group->epoll_fd, POLLIN);
}

static void
poll_group_epoll_get_events(struct poll_group *group_)
{
    struct poll_group_epoll *group = poll_group_epoll_cast(group_);
    size_t n_joined = group_->n_joined;
    int retval, i;

    retval =epoll_wait(group->epoll_fd, group->events, n_joined, 0);

    if (retval == -1) {
        VLOG_ERR("epoll_ctl(EPOLL_CTL_MOD): %s", ovs_strerror(errno));
        retval = errno;
    } else {
        /* Deliver the caller events to the parent calss */
        for (i = 0; i < retval; i ++)  {
            struct epoll_event *event = &group->events[i];
            poll_group_notify(group_, event->data.ptr);
        }
    }
}


const struct poll_group_class poll_group_default_class = {
     "epoll",                      /* name */
     poll_group_epoll_create,      /* create */
     poll_group_epoll_close,       /* close */

     poll_group_epoll_join,        /* join */
     poll_group_epoll_update,      /* update */
     poll_group_epoll_leave,       /* leave */

     poll_group_epoll_poll_wait,   /* poll wait */
     poll_group_epoll_get_events   /* get events */
};
