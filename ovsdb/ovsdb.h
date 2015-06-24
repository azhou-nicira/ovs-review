/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef OVSDB_OVSDB_H
#define OVSDB_OVSDB_H 1

#include "compiler.h"
#include "hmap.h"
#include "list.h"
#include "shash.h"
#include "sset.h"

struct json;
struct ovsdb_log;
struct ovsdb_session;
struct ovsdb_txn;
struct simap;
struct uuid;

/* Database schema. */
struct ovsdb_schema {
    char *name;
    char *version;
    char *cksum;
    struct shash tables;        /* Contains "struct ovsdb_table_schema *"s. */
};

struct ovsdb_schema *ovsdb_schema_create(const char *name,
                                         const char *version,
                                         const char *cksum);
struct ovsdb_schema *ovsdb_schema_clone(const struct ovsdb_schema *);
void ovsdb_schema_destroy(struct ovsdb_schema *);

struct ovsdb_error *ovsdb_schema_from_file(const char *file_name,
                                           struct ovsdb_schema **)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_schema_from_json(struct json *,
                                           struct ovsdb_schema **)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_schema_to_json(const struct ovsdb_schema *);

/* Multiple schemas. */
struct shash *ovsdb_schemas_clone(const struct shash *schemas);
struct ovsdb_error *ovsdb_schemas_from_files(const struct sset *files,
                                             struct shash** )
    OVS_WARN_UNUSED_RESULT;
void ovsdb_schemas_destroy(struct shash *schemas);
struct json *ovsdb_schemas_to_json(const struct shash *schemas)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_schemas_from_json(struct json *json,
                                             struct shash **)
    OVS_WARN_UNUSED_RESULT;

static inline bool
ovsdb_schemas_is_empty(const struct shash *schemas)
{
    return (!shash_count(schemas));
}

static inline bool
ovsdb_schemas_is_null_or_empty(const struct shash *schemas)
{
    return (!schemas || ovsdb_schemas_is_empty(schemas));
}


static inline bool
ovsdb_schemas_is_non_empty(const struct shash *schemas)
{
    return (schemas && !ovsdb_schemas_is_empty(schemas));
}


bool ovsdb_schema_equal(const struct ovsdb_schema *,
                        const struct ovsdb_schema *);

struct ovsdb_error *ovsdb_schemas_join(const struct shash *schemas,
                                       struct ovsdb_schema **)
    OVS_WARN_UNUSED_RESULT;

/* Database. */
struct ovsdb {
    struct ovsdb_schema *schema; /* The joined schema for run time.  */
    struct shash *schemas;       /* The schemas stored in the DB file. */
    struct ovs_list replicas;    /* Contains "struct ovsdb_replica"s. */
    struct shash tables;         /* Contains "struct ovsdb_table *"s. */

    /* Triggers. */
    struct ovs_list triggers;   /* Contains "struct ovsdb_trigger"s. */
    bool run_triggers;
};

struct ovsdb *ovsdb_create(struct ovsdb_schema *schema, struct shash *schemas);
void ovsdb_destroy(struct ovsdb *);

void ovsdb_get_memory_usage(const struct ovsdb *, struct simap *usage);

struct ovsdb_table *ovsdb_get_table(const struct ovsdb *, const char *);

struct json *ovsdb_execute(struct ovsdb *, const struct ovsdb_session *,
                           const struct json *params,
                           long long int elapsed_msec,
                           long long int *timeout_msec);

/* Database replication. */

struct ovsdb_replica {
    struct ovs_list node;       /* Element in "struct ovsdb" replicas list. */
    const struct ovsdb_replica_class *class;
};

struct ovsdb_replica_class {
    struct ovsdb_error *(*commit)(struct ovsdb_replica *,
                                  const struct ovsdb_txn *, bool durable);
    void (*destroy)(struct ovsdb_replica *);
};

void ovsdb_replica_init(struct ovsdb_replica *,
                        const struct ovsdb_replica_class *);

void ovsdb_add_replica(struct ovsdb *, struct ovsdb_replica *);
void ovsdb_remove_replica(struct ovsdb *, struct ovsdb_replica *);

#endif /* ovsdb/ovsdb.h */
