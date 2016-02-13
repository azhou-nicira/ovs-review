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
#include "poll-group.h"
#include "poll-group-provider.h"
#include "poll-loop.h"


struct fds_array {
    struct pollfd *pollfds;   /* array of 'n_jointed'  */
    size_t n_allocated;
};

static void fds_array_init(struct fds_array *fda);
static void fds_array_add_fd(struct fds_array *fda, int fd, size_t n);
static void fds_array_clear_fd(struct fds_array *fda, size_t index, size_t n);
static bool fds_array_find_fd(struct fds_array *fda, int fd, size_t n,
                              size_t *index);
static void fds_array_update(struct fds_array *fda, size_t index, int fd,
                             bool write);
static void fds_array_destroy(struct fds_array *fda);
static void fds_array_poll_wait(struct fds_array *fda, size_t n);


struct poll_group_default {
    struct poll_group up;
    struct fds_array fds;      /* array of 'n_jointed' fds  */
};


static struct poll_group_default *
poll_group_default_cast(struct poll_group *group)
{
    poll_group_assert_class(group, &poll_group_default_class);
    return CONTAINER_OF(group, struct poll_group_default, up);
}

static struct poll_group *
poll_group_default_create(const char *name)
{
    struct poll_group_default *group;

    group = xmalloc(sizeof *group);
    poll_group_init(&group->up, name, &poll_group_default_class);
    fds_array_init(&group->fds);

    return &group->up;
}

static void
poll_group_default_close(struct poll_group *group_)
{
    struct poll_group_default *group = poll_group_default_cast(group_);

    fds_array_destroy(&group->fds);
    free(group);
}

static int
poll_group_default_join(struct poll_group *group_, int fd, void *caller_event)
{
    struct poll_group_default *group = poll_group_default_cast(group_);
    size_t index, n_joined = group_->n_joined;

    bool found = fds_array_find_fd(&group->fds, fd, n_joined, &index);
    if (found) {
        return PG_ERROR_DUPLICATED_FD;
    }

    fds_array_add_fd(&group->fds, fd, n_joined);
    poll_fd_register(fd, group_, caller_event);

    return 0;
}

static int
poll_group_default_leave(struct poll_group *group_, int fd)
{
    struct poll_group_default *group = poll_group_default_cast(group_);
    size_t index, n_joined = group_->n_joined;

    bool found = fds_array_find_fd(&group->fds, fd, n_joined, &index);
    if (!found) {
        return PG_ERROR_FD_NOT_FOUND;
    }

    poll_fd_unregister(fd);
    fds_array_clear_fd(&group->fds, index, n_joined);

    return 0;
}

static int
poll_group_default_update(struct poll_group *group_, int fd, bool write)
{
    struct poll_group_default *group = poll_group_default_cast(group_);
    size_t index, n_joined = group_->n_joined;

    bool found = fds_array_find_fd(&group->fds, fd, n_joined, &index);
    if (!found) {
        return PG_ERROR_FD_NOT_FOUND;
    }

    fds_array_update(&group->fds, index, fd, write);

    return 0;
}

static void
poll_group_default_poll_wait(struct poll_group *group_)
{
    struct poll_group_default *group = poll_group_default_cast(group_);
    size_t n_joined = group_->n_joined;

    fds_array_poll_wait(&group->fds, n_joined);
}


static void
fds_array_init(struct fds_array *fda)
{
    fda->pollfds = NULL;
    fda->n_allocated = 0;
}

static bool
fds_array_find_fd(struct fds_array *fda, int fd, size_t n, size_t *index)
{
    struct pollfd *pollfds = fda->pollfds;
    size_t i;

    ovs_assert(n <= fda->n_allocated);
    for (i = 0; i < n; i++) {
        if (pollfds[i].fd == fd) {
            *index = i;
            break;
        }
    }

    return (i!=n);
}

static void
fds_array_add_fd(struct fds_array *fda, int fd, size_t n)
{
    struct pollfd *pollfds = fda->pollfds;

    if (n >= fda->n_allocated) {
        pollfds = x2nrealloc(pollfds, &fda->n_allocated, sizeof *pollfds);
        fda->pollfds = pollfds;
    }

    fds_array_update(fda, n, fd, false);
}

static void
fds_array_clear_fd(struct fds_array *fda, size_t index, size_t n)
{
    struct pollfd *pollfds = fda->pollfds;
    size_t last = n - 1;
   
    ovs_assert(n);
    /* Use the last entry to overwite this fd */
    if (index != last) {
        pollfds[index] = pollfds[last];
    }
}

static void
fds_array_update(struct fds_array *fda, size_t index, int fd, bool write)
{
    struct pollfd *pollfds = fda->pollfds;

    ovs_assert(index <= fda->n_allocated);

    pollfds[index].fd = fd;
    pollfds[index].events = POLLIN | (write ? POLLOUT : 0);
}

static void
fds_array_destroy(struct fds_array *fda)
{
    free(fda->pollfds);
}

static void
fds_array_poll_wait(struct fds_array *fda, size_t n)
{
    size_t i;

    ovs_assert(n <= fda->n_allocated);

    for (i = 0; i < n; i++) {
        struct pollfd *pollfd= &fda->pollfds[i];
        poll_fd_wait(pollfd->fd, pollfd->events);
    }
}


const struct poll_group_class poll_group_default_class = {
     "default",                      /* name */
     poll_group_default_create,      /* create */
     poll_group_default_close,       /* close */

     poll_group_default_join,        /* join */
     poll_group_default_update,      /* update */
     poll_group_default_leave,       /* leave */

     poll_group_default_poll_wait,   /* poll wait */
     NULL,                           /* get events */ 
};
