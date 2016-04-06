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

#ifndef POLL_GROUP_H
#define POLL_GROUP_H 1

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "openvswitch/types.h"

struct poll_group;

#if 0
enum {
    PG_ERROR_NO_ERROR,       /* Success */
    PG_ERROR_NO_GROUP,
    PG_ERROR_NO_CLASS,
    PG_ERROR_INVALID_CLASS,
    PG_ERROR_DUPLICATED_FD,
    PG_ERROR_FD_NOT_FOUND,
};
#endif

/* To be called by stream class implementation. */
int poll_group_join(struct poll_group *group, int fd, void *caller_id);
int poll_group_update(struct poll_group *group, int fd, bool write,
                      void *caller_id);
int poll_group_leave(struct poll_group *group, int fd);

/* APIs called by applications. */
struct poll_group *poll_group_create(void);
void poll_group_close(struct poll_group *group);
void poll_group_poll_wait(struct poll_group *group);
void poll_group_get_events(struct poll_group *, void** caller_ids, size_t *n);

/* Poll group is currently only supported on Linux platform. */
#ifndef __linux__
static inline int
poll_group_join(struct poll_group *group OVS_UNUSED,
                int fd OVS_UNUSED, void *caller_id OVS_UNUSED) {
   return -1;
}

static inline int
poll_group_update(struct poll_group *group OVS_UNUSED,
                  int fd OVS_UNUSED, bool write OVS_UNUSED,
                  void *caller_id OVS_UNUSED)
{
    return -1;
}

static inline int
poll_group_leave(struct poll_group *group OVS_UNUSED, int fd OVS_UNUSED)
{
    return -1;
}

static inline struct poll_group *
poll_group_create(void)
{
    return NULL;
}

static inline void
poll_group_close(struct poll_group *group OVS_UNUSED)
{
    return;
}
static inline void
poll_group_poll_wait(struct poll_group *group OVS_UNUSED)
{
    return;
}

static inline void
poll_group_get_events(struct poll_group * OVS_UNUSED,
                      void** caller_ids OVS_UNUSED, size_t *n OVS_UNUSED)
{
    return;
}
#endif  /* ifndef __linux__ */

#endif /* poll-group.h */
