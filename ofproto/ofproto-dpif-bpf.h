/*
 * Copyright (c) 2015 Nicira, Inc.
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
#ifndef OFPROTO_DPIF_BPF_H
#define OFPROTO_DPIF_BPF_H

#ifdef __linux__
int ofproto_dpif_bpf_init(bool enable);
void ofproto_dpif_bpf_close(void);
int ofproto_dpif_bpf_lookup(const char *bpf_prog_name);
#else
static inline int
ofproto_dpif_bpf_init(bool enable)
{
    return 0;
}

static void
ofproto_dpif_bpf_close(void)
{
}

static int
ofproto_dpif_bpf_lookup(const char *bpf_prog_name)
{
    return -2;
}
#endif

#endif
