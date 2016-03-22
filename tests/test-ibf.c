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
#undef NDEBUG
#include "util.h"
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "byte-order.h"
#include "command-line.h"
#include "hash.h"
#include "ibf.h"
#include "ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovstest.h"
#include "timeval.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(test_ibf);

static void
read_uuids_from_file(const char *filename, struct ofpbuf *buf)
{
    FILE *file;
    char line[128];

    file = fopen(filename, "r");
    ofpbuf_init(buf, 0);

    if (!file) {
        ovs_abort(0, "File %s not found", filename);
    }

    while (fgets(line, sizeof line, file)) {
        struct uuid uuid;

        line[UUID_LEN] = '\0';
        if (!uuid_from_string(&uuid, line)) {
            ofpbuf_uninit(buf);
            fclose(file);
            ovs_abort(0, "Can't read uuid from file %s", filename);
        }

        ofpbuf_put(buf, &uuid, sizeof uuid);
    }

    fclose(file);
}

static void
key_uuid_to_ds(struct ds *ds, const void *uuid_)
{
    const struct uuid *uuid = uuid_;

    ds_put_format(ds, UUID_FMT, UUID_ARGS(uuid));
}

static uint32_t
key_uuid_hash(const void *uuid_, uint32_t basis)
{
    const struct uuid *uuid = uuid_;

    return hash_int(uuid_hash(uuid), basis);
}

static bool
key_uuid_equals(const void *uuid1_, const void *uuid2_)
{
    const struct uuid *uuid1 = uuid1_;
    const struct uuid *uuid2 = uuid2_;

    return uuid_equals(uuid1, uuid2);
}

static void
key_uuid_xor(void *uuid1_, const void *uuid2_)
{
    struct uuid *a = uuid1_;
    const struct uuid *b = uuid2_;

    a->parts[0] ^= b->parts[0];
    a->parts[1] ^= b->parts[1];
    a->parts[2] ^= b->parts[2];
    a->parts[3] ^= b->parts[3];
}

static bool
key_uuid_is_zero(const void *uuid_)
{
    const struct uuid *u = uuid_;

    return uuid_is_zero(u);
}

static void
log_ibf(struct ibf *ibf, char *log_title)
{
    struct ds ds;
    char *s;

    ds_init(&ds);
    ds_put_format(&ds, "%s:\n", log_title);
    ibf_to_ds(&ds, ibf);
    s = ds_steal_cstr(&ds);
    VLOG_INFO("%s", s);
    free(s);
}

static struct ibf *
create_ibf(struct ofpbuf *buf, unsigned int n_keys, struct ibf_key_ops *ops)
{
    struct ibf *ibf;
    struct uuid *uuid;
    size_t key_size= sizeof *uuid;

    ibf = ibf_create(key_size, n_keys, ops);

    while(buf->size) {
        uuid = ofpbuf_pull(buf, key_size);
        ibf_add_key(ibf, uuid);
    }

    return ibf;
}

static void
dump_ibf_key_hmap(struct hmap *map, const char *log_title)
{
    struct ibf_key_hmap_node *key_node;
    printf("%s(%"PRIuSIZE"):\n", log_title, hmap_count(map));

    HMAP_FOR_EACH (key_node, hmap_node, map) {
        struct uuid *uuid = (struct uuid *)(void*)key_node->key;

        printf(UUID_FMT"\n", UUID_ARGS(uuid));
    }
}

static void
key_ops_init(struct ibf_key_ops *ops)
{
    ops->to_ds = key_uuid_to_ds;
    ops->hash = key_uuid_hash;
    ops->equals = key_uuid_equals;
    ops->xor = key_uuid_xor;
    ops->is_zero = key_uuid_is_zero;
}

static double
get_execution_time(struct timeval *start, struct timeval *end)
{
   return (1000*(double)(end->tv_sec - start->tv_sec))
            + (.001*(end->tv_usec - start->tv_usec));
}

static void
decode(struct ovs_cmdl_context *ctx, bool enable_log_ibf)
{
#define LOG_IBF if (enable_log_ibf) log_ibf
    struct ofpbuf a, b;
    struct hmap added, deleted;
    struct ibf *ibf, *ibf_b;
    unsigned int d;
    struct ibf_key_ops key_ops;
    struct timeval start, end;

    key_ops_init(&key_ops);

    read_uuids_from_file(ctx->argv[1], &a);
    read_uuids_from_file(ctx->argv[2], &b);
    d = atoi(ctx->argv[3]);

    xgettimeofday(&start);
    ibf = create_ibf(&a, d, &key_ops);
    LOG_IBF(ibf, ctx->argv[1]);
    ibf_b = create_ibf(&b, d, &key_ops);
    LOG_IBF(ibf_b, ctx->argv[2]);
    ibf_substract(ibf, ibf_b);
    LOG_IBF(ibf, "delta");
    xgettimeofday(&end);

    if (ibf_decode(ibf, &added, &deleted)) {
        dump_ibf_key_hmap(&added, "added:");
        dump_ibf_key_hmap(&deleted, "deleted:");
        if (!enable_log_ibf) {
            /* Timing information will not be useful if 'enable_log_ibf'
             * is turned on. Only report it if we don't log ibf. */
            VLOG_INFO("time: %.1f ms", get_execution_time(&start, &end));
        }
    } else {
        printf("Decode failed.\n");
    }
}

static void
test_decode(struct ovs_cmdl_context *ctx)
{
    decode(ctx, true);
}

static void
decode_benchmark(struct ovs_cmdl_context *ctx)
{
    decode(ctx, false);
}

static uint32_t
num_uuids(struct ofpbuf *buf)
{
    return buf->size / sizeof (struct uuid);
}

static void
fill_estimator(struct ibf_strata_estimator *e, struct ofpbuf *buf)
{
    struct uuid *uuid;

    while(buf->size) {
        uuid = ofpbuf_pull(buf, sizeof (struct uuid));
        ibf_estimator_add_key(e, uuid);
    }
}

static void
test_estimate(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf a, b;
    unsigned int n_ibfs;
    struct ibf_key_ops key_ops;
    uint32_t a_size, b_size;
    struct ibf_strata_estimator *ae, *be;
    struct timeval start, end;
    unsigned int d;

    key_ops_init(&key_ops);

    read_uuids_from_file(ctx->argv[1], &a);
    read_uuids_from_file(ctx->argv[2], &b);

    a_size = num_uuids(&a);
    b_size = num_uuids(&b);

    n_ibfs = MAX(log_2_ceil(a_size), log_2_ceil(b_size));

    if (n_ibfs == 32) {
        ovs_abort(0, "Files %s and %s are both empty, abort", ctx->argv[1],
                  ctx->argv[2]);
    }

    VLOG_INFO("File %s has %"PRIu32" uuids, log(size): %"PRIu32,
              ctx->argv[1], a_size, log_2_ceil(a_size));
    VLOG_INFO("File %s has %"PRIu32" uuids, log(size): %"PRIu32,
              ctx->argv[2], b_size, log_2_ceil(b_size));
    VLOG_INFO("NUM IBF tables per estimator: %"PRIu32, n_ibfs);

    ae = ibf_create_estimator(n_ibfs, sizeof (struct uuid), &key_ops);
    fill_estimator(ae, &a);
    xgettimeofday(&start);
    be = ibf_create_estimator(n_ibfs, sizeof (struct uuid), &key_ops);
    fill_estimator(be, &b);
    d = ibf_estimate_delta(ae, be);

    ibf_estimator_destroy(ae);
    free(ae);
    ibf_estimator_destroy(be);
    free(be);
    xgettimeofday(&end);

    printf("Estimated differneces: %u\n", d);
    VLOG_INFO("time: %.1f ms", get_execution_time(&start, &end));
}


static const struct ovs_cmdl_command commands[] = {
    {"decode", NULL, 3, 3, test_decode},
    {"decode-bm", NULL, 3, 3, decode_benchmark},
    {"estimate", NULL, 2, 2, test_estimate},
    {NULL, NULL, 0, 0, NULL},
};

static void
parse_options(int argc, char *argv[])
{
    enum {
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
test_ibf_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = { .argc = 0, };
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_SYSLOG, VLL_OFF);
    vlog_set_levels_from_string_assert("test_ibf:console:emer");
    parse_options(argc, argv);
    /* On Windows, stderr is fully buffered if connected to a pipe.
     * Make it _IONBF so that an abort does not miss log contents.
     * POSIX doesn't define the circumstances in which stderr is
     * fully buffered either. */
    setvbuf(stderr, NULL, _IONBF, 0);
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ibf", test_ibf_main);
