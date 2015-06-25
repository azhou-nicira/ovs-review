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

#include <config.h>

#include "ovsdb.h"

#include "column.h"
#include "dynamic-string.h"
#include "json.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-types.h"
#include "simap.h"
#include "sset.h"
#include "table.h"
#include "transaction.h"

static struct ovsdb_schema *
ovsdb_schema_create(const char *name, const char *version, const char *cksum)
{
    struct ovsdb_schema *schema;

    schema = xzalloc(sizeof *schema);
    schema->name = xstrdup(name);
    schema->version = xstrdup(version);
    schema->cksum = xstrdup(cksum);
    shash_init(&schema->tables);

    return schema;
}

static struct ovsdb_schema *
ovsdb_schema_clone(const struct ovsdb_schema *old)
{
    struct ovsdb_schema *new;
    struct shash_node *node;

    new = ovsdb_schema_create(old->name, old->version, old->cksum);
    SHASH_FOR_EACH (node, &old->tables) {
        const struct ovsdb_table_schema *ts = node->data;

        shash_add(&new->tables, node->name, ovsdb_table_schema_clone(ts));
    }
    return new;
}

void
ovsdb_schema_destroy(struct ovsdb_schema *schema)
{
    struct shash_node *node;

    if (!schema) {
        return;
    }

    SHASH_FOR_EACH (node, &schema->tables) {
        ovsdb_table_schema_destroy(node->data);
    }
    shash_destroy(&schema->tables);
    free(schema->name);
    free(schema->version);
    free(schema->cksum);
    free(schema);
}

/* Join two schemas into a single schema, by adding missing tables from 'src'
 * to 'dst'. In case 'src' and 'dst' both has the same table, the joined 'dst' table
 * will contain the columns from both 'src' and 'dst' tables. 
 * 
 * The joined schema name will be the concatenation of each schema's name,
 * sperated by a comma and a space.  */
static struct ovsdb_error *
ovsdb_schema_join(struct ovsdb_schema *dst, const struct ovsdb_schema *src)
{
    struct shash_node *snode;
    struct ds ds;

    /* Combine schema names into a comma seperated string.  */
    ds_init(&ds);

    /* XXX How should we generate the name for the joined schema? */
    /* For now, Name starts with 'O' will be taken over the name
     * without it */
    ds_put_format(&ds, "%s", (*dst->name == 'O') ? dst->name : src->name);
    free(dst->name);
    dst->name = ds_steal_cstr(&ds);

    SHASH_FOR_EACH (snode, &src->tables) {
        const struct ovsdb_table_schema *sts = snode->data;
        struct shash_node *dnode;

        dnode = shash_find(&dst->tables, sts->name);
        if (dnode) {
            struct ovsdb_table_schema *dts = dnode->data;
            struct ovsdb_error *err;

            err = ovsdb_table_schema_join(dts, sts);
            if (err) {
                return err;
            }
        } else {
            shash_add(&dst->tables, sts->name, ovsdb_table_schema_clone(sts));
        }
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_schema_from_file(const char *file_name, struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;
    struct json *json;

    *schemap = NULL;
    json = json_from_file(file_name);
    if (json->type == JSON_STRING) {
        error = ovsdb_error("failed to read schema",
                           "\"%s\" could not be read as JSON (%s)",
                           file_name, json_string(json));
        json_destroy(json);
        return error;
    }

    error = ovsdb_schema_from_json(json, &schema);
    json_destroy(json);
    if (error) {
        return ovsdb_wrap_error(error,
                                "failed to parse \"%s\" as ovsdb schema",
                                file_name);
    }

    *schemap = schema;
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_schema_check_ref_table(struct ovsdb_column *column,
                             const struct shash *tables,
                             const struct ovsdb_base_type *base,
                             const char *base_name)
{
    struct ovsdb_table_schema *refTable;

    if (base->type != OVSDB_TYPE_UUID || !base->u.uuid.refTableName) {
        return NULL;
    }

    refTable = shash_find_data(tables, base->u.uuid.refTableName);
    if (!refTable) {
        return ovsdb_syntax_error(NULL, NULL,
                                  "column %s %s refers to undefined table %s",
                                  column->name, base_name,
                                  base->u.uuid.refTableName);
    }

    if (ovsdb_base_type_is_strong_ref(base) && !refTable->is_root) {
        /* We cannot allow a strong reference to a non-root table to be
         * ephemeral: if it is the only reference to a row, then replaying the
         * database log from disk will cause the referenced row to be deleted,
         * even though it did exist in memory.  If there are references to that
         * row later in the log (to modify it, to delete it, or just to point
         * to it), then this will yield a transaction error. */
        column->persistent = true;
    }

    return NULL;
}

static bool
is_valid_version(const char *s)
{
    int n = -1;
    ignore(ovs_scan(s, "%*[0-9].%*[0-9].%*[0-9]%n", &n));
    return n != -1 && s[n] == '\0';
}

/* Returns the number of tables in 'schema''s root set. */
static size_t
root_set_size(const struct ovsdb_schema *schema)
{
    struct shash_node *node;
    size_t n_root = 0;

    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;

        n_root += table->is_root;
    }
    return n_root;
}

struct ovsdb_error *
ovsdb_schema_from_json(struct json *json, struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema;
    const struct json *name, *tables, *version_json, *cksum;
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_parser parser;
    const char *version;

    *schemap = NULL;

    ovsdb_parser_init(&parser, json, "database schema");
    name = ovsdb_parser_member(&parser, "name", OP_ID);
    version_json = ovsdb_parser_member(&parser, "version",
                                       OP_STRING | OP_OPTIONAL);
    cksum = ovsdb_parser_member(&parser, "cksum", OP_STRING | OP_OPTIONAL);
    tables = ovsdb_parser_member(&parser, "tables", OP_OBJECT);
    error = ovsdb_parser_finish(&parser);
    if (error) {
        return error;
    }

    if (version_json) {
        version = json_string(version_json);
        if (!is_valid_version(version)) {
            return ovsdb_syntax_error(json, NULL, "schema version \"%s\" not "
                                      "in format x.y.z", version);
        }
    } else {
        /* Backward compatibility with old databases. */
        version = "";
    }

    schema = ovsdb_schema_create(json_string(name), version,
                                 cksum ? json_string(cksum) : "");
    SHASH_FOR_EACH (node, json_object(tables)) {
        struct ovsdb_table_schema *table;

        if (node->name[0] == '_') {
            error = ovsdb_syntax_error(json, NULL, "names beginning with "
                                       "\"_\" are reserved");
        } else if (!ovsdb_parser_is_id(node->name)) {
            error = ovsdb_syntax_error(json, NULL, "name must be a valid id");
        } else {
            error = ovsdb_table_schema_from_json(node->data, node->name,
                                                 &table);
        }
        if (error) {
            ovsdb_schema_destroy(schema);
            return error;
        }

        shash_add(&schema->tables, table->name, table);
    }

    /* "isRoot" was not part of the original schema definition.  Before it was
     * added, there was no support for garbage collection.  So, for backward
     * compatibility, if the root set is empty then assume that every table is
     * in the root set. */
    if (root_set_size(schema) == 0) {
        SHASH_FOR_EACH (node, &schema->tables) {
            struct ovsdb_table_schema *table = node->data;

            table->is_root = true;
        }
    }

    /* Validate that all refTables refer to the names of tables that exist.
     *
     * Also force certain columns to be persistent, as explained in
     * ovsdb_schema_check_ref_table().  This requires 'is_root' to be known, so
     * this must follow the loop updating 'is_root' above. */
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        struct shash_node *node2;

        SHASH_FOR_EACH (node2, &table->columns) {
            struct ovsdb_column *column = node2->data;

            error = ovsdb_schema_check_ref_table(column, &schema->tables,
                                                 &column->type.key, "key");
            if (!error) {
                error = ovsdb_schema_check_ref_table(column, &schema->tables,
                                                     &column->type.value,
                                                     "value");
            }
            if (error) {
                ovsdb_schema_destroy(schema);
                return error;
            }
        }
    }

    *schemap = schema;
    return NULL;
}

struct json *
ovsdb_schema_to_json(const struct ovsdb_schema *schema)
{
    struct json *json, *tables;
    struct shash_node *node;
    bool default_is_root;

    json = json_object_create();
    json_object_put_string(json, "name", schema->name);
    if (schema->version[0]) {
        json_object_put_string(json, "version", schema->version);
    }
    if (schema->cksum[0]) {
        json_object_put_string(json, "cksum", schema->cksum);
    }

    /* "isRoot" was not part of the original schema definition.  Before it was
     * added, there was no support for garbage collection.  So, for backward
     * compatibility, if every table is in the root set then do not output
     * "isRoot" in table schemas. */
    default_is_root = root_set_size(schema) == shash_count(&schema->tables);

    tables = json_object_create();

    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        json_object_put(tables, table->name,
                        ovsdb_table_schema_to_json(table, default_is_root));
    }
    json_object_put(json, "tables", tables);

    return json;
}

/* Returns true if 'a' and 'b' specify equivalent schemas, false if they
 * differ. */
bool
ovsdb_schema_equal(const struct ovsdb_schema *a,
                   const struct ovsdb_schema *b)
{
    /* This implementation is simple, stupid, and slow, but I doubt that it
     * will ever require much maintenance. */
    struct json *ja = ovsdb_schema_to_json(a);
    struct json *jb = ovsdb_schema_to_json(b);
    bool equals = json_equal(ja, jb);
    json_destroy(ja);
    json_destroy(jb);

    return equals;
}

static void
ovsdb_set_ref_table(const struct shash *tables,
                    struct ovsdb_base_type *base)
{
    if (base->type == OVSDB_TYPE_UUID && base->u.uuid.refTableName) {
        struct ovsdb_table *table;

        table = shash_find_data(tables, base->u.uuid.refTableName);
        base->u.uuid.refTable = table;
    }
}

struct ovsdb *
ovsdb_create(struct ovsdb_schema *schema, struct shash *schemas)
{
    struct shash_node *node;
    struct ovsdb *db;

    db = xmalloc(sizeof *db);
    db->schema = schema;
    db->schemas = schemas;
    list_init(&db->replicas);
    list_init(&db->triggers);
    db->run_triggers = false;

    shash_init(&db->tables);
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;
        shash_add(&db->tables, node->name, ovsdb_table_create(ts));
    }

    /* Set all the refTables. */
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table = node->data;
        struct shash_node *node2;

        SHASH_FOR_EACH (node2, &table->columns) {
            struct ovsdb_column *column = node2->data;

            ovsdb_set_ref_table(&db->tables, &column->type.key);
            ovsdb_set_ref_table(&db->tables, &column->type.value);
        }
    }

    return db;
}

void
ovsdb_destroy(struct ovsdb *db)
{
    if (db) {
        struct shash_node *node;

        /* Remove all the replicas. */
        while (!list_is_empty(&db->replicas)) {
            struct ovsdb_replica *r
                = CONTAINER_OF(list_pop_back(&db->replicas),
                               struct ovsdb_replica, node);
            ovsdb_remove_replica(db, r);
        }

        /* Delete all the tables.  This also deletes their schemas. */
        SHASH_FOR_EACH (node, &db->tables) {
            struct ovsdb_table *table = node->data;
            ovsdb_table_destroy(table);
        }
        shash_destroy(&db->tables);

        /* The schemas, but not the table that points to them, were deleted in
         * the previous step, so we need to clear out the table.  We can't
         * destroy the table, because ovsdb_schema_destroy() will do that. */
        shash_clear(&db->schema->tables);

        ovsdb_schema_destroy(db->schema);
        if (db->schemas) {
            ovsdb_schemas_destroy(db->schemas);
        }
        free(db);
    }
}

/* Adds some memory usage statistics for 'db' into 'usage', for use with
 * memory_report(). */
void
ovsdb_get_memory_usage(const struct ovsdb *db, struct simap *usage)
{
    const struct shash_node *node;
    unsigned int cells = 0;

    SHASH_FOR_EACH (node, &db->tables) {
        const struct ovsdb_table *table = node->data;
        unsigned int n_columns = shash_count(&table->schema->columns);
        unsigned int n_rows = hmap_count(&table->rows);

        cells += n_rows * n_columns;
    }

    simap_increase(usage, "cells", cells);
}

struct ovsdb_table *
ovsdb_get_table(const struct ovsdb *db, const char *name)
{
    return shash_find_data(&db->tables, name);
}

void
ovsdb_replica_init(struct ovsdb_replica *r,
                   const struct ovsdb_replica_class *class)
{
    r->class = class;
}

void
ovsdb_add_replica(struct ovsdb *db, struct ovsdb_replica *r)
{
    list_push_back(&db->replicas, &r->node);
}

void
ovsdb_remove_replica(struct ovsdb *db OVS_UNUSED, struct ovsdb_replica *r)
{
    list_remove(&r->node);
    (r->class->destroy)(r);
}

/* Join each schema within 'schemas' into a single joined schema.
 * 'schemas' passed in should have at least one schema.
 *
 * On success, this function returns NULL, 'schemap' points to the newly created
 * joined schema. The caller is responsible for reclaiming memory via
 * ovsdb_schema_destroy().
 *
 * On error, an ovsdb_error will be allocated describing the error, the caller
 * is only needs to dispose memory of the error. */
struct ovsdb_error *
ovsdb_schemas_join(const struct shash *schemas, struct ovsdb_schema **schemap)
{
    struct shash_node *first_node = shash_first(schemas), *node;
    struct ovsdb_schema *schema;

    ovs_assert(first_node);
    schema = ovsdb_schema_clone(first_node->data);

    SHASH_FOR_EACH (node, schemas) {
        struct ovsdb_error *error;

        if (node == first_node) {
            continue;
        }

        error = ovsdb_schema_join(schema, node->data);
        if (error) {
            ovsdb_schema_destroy(schema);
            *schemap = NULL;
            return error;
        }
    }

    *schemap = schema;
    return NULL;
}

void
ovsdb_schemas_destroy(struct shash *schemas)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, schemas) {
        struct ovsdb_schema *schema = node->data;

        shash_delete(schemas, node);
        ovsdb_schema_destroy(schema);
    }
    shash_destroy(schemas);
    free(schemas);
}

struct shash *
ovsdb_schemas_clone(const struct shash *schemas)
{
    struct shash_node *node;
    struct shash *new_schemas;

    new_schemas = xmalloc(sizeof *new_schemas);
    shash_init(new_schemas);

    SHASH_FOR_EACH (node, schemas) {
        struct ovsdb_schema *schema = node->data;

        shash_add(new_schemas, schema->name, ovsdb_schema_clone(schema));
    }

    return new_schemas;

}

struct ovsdb_error *
ovsdb_schemas_from_files(const struct sset *files, struct shash **schemasp)
{
    struct ovsdb_error *err;
    struct shash *schemas;
    const char *filename;

    ovs_assert(schemasp);

    schemas = xmalloc(sizeof *schemas);
    shash_init(schemas);

    SSET_FOR_EACH(filename, files) {
        struct ovsdb_schema *schema;

        err = ovsdb_schema_from_file(filename, &schema);
        if (err) {
            goto error;
        };

        if (shash_find(schemas, schema->name)) {
            err = ovsdb_error("schemas read", "duplicated schema names");
	    ovsdb_schema_destroy(schema);
            goto error;
        };

        shash_add(schemas, schema->name, schema);
    }

    *schemasp = schemas;
    return NULL;

error:
    ovsdb_schemas_destroy(schemas);
    *schemasp = NULL;

    return err;
}

struct json *
ovsdb_schemas_to_json(const struct shash *schemas)
{
    switch (shash_count(schemas)) {
    case 0:
        return NULL;

    case 1:
        {
            struct shash_node *node;
            struct ovsdb_schema *schema;

            node = shash_first(schemas);
            schema = node->data;

            return ovsdb_schema_to_json(schema);
        }

    default:
        {
            struct json *json_schemas;
            struct shash_node *node;

            json_schemas = json_array_create_empty();
            SHASH_FOR_EACH (node, schemas) {
                struct ovsdb_schema *schema = node->data;
                json_array_add(json_schemas, ovsdb_schema_to_json(schema));
            }
            return json_schemas;
        }
    }
}

struct ovsdb_error *
ovsdb_schemas_from_json(struct json *json, struct shash **schemasp)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *err;
    struct shash *schemas;

    schemas = xmalloc(sizeof *schemas);
    shash_init(schemas);

    switch (json->type) {
    case JSON_OBJECT:
        err = ovsdb_schema_from_json(json, &schema);
        if (err) {
            goto error;
        }
        shash_add(schemas, schema->name, schema);
        break;

    case JSON_ARRAY:
        {
            struct json_array *array = json_array(json);
            size_t i;

            for(i = 0; i < array->n; i++) {
                err = ovsdb_schema_from_json(array->elems[i], &schema);

                if (err) {
                    goto error;
                }
                shash_add(schemas, schema->name, schema);
            }
        }
        break;

    case JSON_NULL:
    case JSON_FALSE:
    case JSON_TRUE:
    case JSON_INTEGER:
    case JSON_REAL:
    case JSON_STRING:
    case JSON_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }

    *schemasp = schemas;
    return NULL;

error:
    ovsdb_schemas_destroy(schemas);
    free(schemas);
    *schemasp = NULL;

    return err;
}

/*
 * Parse schema file names from a string.
 *
 * A leading comma indicates the default schema name.
 *
 * Duplicated filenames will be ignored.   */
void
ovsdb_parse_schema_file_names(const char *file_names, struct sset *name_set,
                              const char *default_schema)
{
    const char *delimiter=", \t\r\n";
    const char *filename;
    char *saveptr;
    char *fns;

    if (!file_names) {
        sset_add(name_set, default_schema);
        return;
    }

    if (*file_names == ',') {
        sset_add(name_set, default_schema);
    }

    fns = xstrdup(file_names);
    filename = strtok_r(fns, delimiter, &saveptr);
    if (!filename) {
        filename = default_schema;
    }

    while(filename) {
        sset_add(name_set, filename);
        filename = strtok_r(NULL, delimiter, &saveptr);
    }
    free(fns);
}
