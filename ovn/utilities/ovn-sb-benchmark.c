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

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "json.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "poll-loop.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovn_sb_benchmark);


struct bm_settings {
    const char *db;
    int num_chassis;
    int num_lswitches;
    int num_lports;
    int num_threads;
};

static void bm_settings_init(struct bm_settings *);
static void bm_settings_print(struct bm_settings *);


static const char *
ovn_sb_benchmark_default_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_SB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovnsb_db.sock", ovs_rundir());
        }
    }
    return def;
}


OVS_NO_RETURN static void usage(void);

/* Global variables. */
static bool verbose = false;
struct bm_settings bm;   /* global settings. */


static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"num-chassis", required_argument, NULL, 'c'},
        {"num-lswitches", required_argument, NULL, 'l'},
        {"num-lports", required_argument, NULL, 'p'},
        {"num-threads", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options;
    short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DB:
            bm.db = optarg;
            break;

        case 'c':
            bm.num_chassis = atoi(optarg);
            break;

        case 'l':
            bm.num_lswitches = atoi(optarg);
            break;

        case 'p':
            bm.num_lports = atoi(optarg);
            break;

        case 't':
            bm.num_threads = atoi(optarg);
            break;

        case 'v':
            verbose = true;
            break;
        case 'h':
            usage();
            break;
        }
    }
}


int
main(int argc, char *argv[])
{
    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    bm_settings_init(&bm);
    parse_options(argc, argv);

    if (ferror(stdout)) {
        VLOG_FATAL("write to stdout failed");
    }
    if (ferror(stderr)) {
        VLOG_FATAL("write to stderr failed");
    }

    bm_settings_print(&bm);

    return 0;
}


static void
bm_settings_to_ds(struct ds *ds, struct bm_settings *bm)
{
    ds_put_format(ds, "db: %s\n", bm->db);
    ds_put_format(ds, "num chassis: %d\n", bm->num_chassis);
    ds_put_format(ds, "num lswitches: %d\n", bm->num_lswitches);
    ds_put_format(ds, "num lports: %d\n", bm->num_lports);
    ds_put_format(ds, "num threads: %d\n", bm->num_threads);
}


static void
bm_settings_init(struct bm_settings *bm)
{
    bm->db = ovn_sb_benchmark_default_db();
    bm->num_threads = 1;
    bm->num_chassis = 1;
    bm->num_lswitches = 1;
    bm->num_lports = 1;
}

static void bm_settings_print(struct bm_settings *bm)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    bm_settings_to_ds(&ds, bm);
    printf("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}


static void
usage(void)
{
    printf("\
%s: OVN southbound DB benchmark tool\n\
\n\
For debugging and testing only, not for use in production.\n\
\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  show                        print overview of database contents\n\
\n\
Chassis commands:\n\
  chassis-add CHASSIS ENCAP-TYPE ENCAP-IP  create a new chassis named\n\
                                           CHASSIS with ENCAP-TYPE tunnels\n\
                                           and ENCAP-IP\n\
  chassis-del CHASSIS         delete CHASSIS and all of its encaps\n\
                              and gateway_ports\n\
\n\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n",
    program_name, program_name);

    vlog_usage();
    exit(EXIT_SUCCESS);
}
