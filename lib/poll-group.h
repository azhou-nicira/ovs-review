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

enum {
    PG_ERROR_NO_ERROR,       /* Success */
    PG_ERROR_NO_GROUP,
    PG_ERROR_NO_CLASS,
    PG_ERROR_INVALID_CLASS,
    PG_ERROR_DUPLICATED_FD,
    PG_ERROR_FD_NOT_FOUND,
};

struct poll_group *poll_group_create(const char *name);
void poll_group_close(struct poll_group *group);

int poll_group_join(struct poll_group *group, int fd, void *caller_event);
int poll_group_update(struct poll_group *group, int fd, bool write);
int poll_group_leave(struct poll_group *group, int fd);

void poll_group_poll_wait(struct poll_group *group);

void poll_group_notify(struct poll_group *, void *caller_event);
void poll_group_get_events(struct poll_group *, void **caller_event, size_t *n);

#endif /* poll-group.h */
