/* Copyright (c) 2015 Nicira, Inc.
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

#include "ovsdb-idl.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#include "jsonrpc.h"
#include "ovsdb/column.h"
#include "ovsdb/ovsdb.h"
#include "ovsdb/row.h"
#include "ovsdb/table.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-idl-class.h"
#include "ovsdb-idl-provider.h"
#include "ovsdb-parser.h"
#include "ovsdb-types.h"
#include "poll-loop.h"
#include "shash.h"
#include "util.h"
#include "openvswitch/vlog.h"

static void
ovsdb_idl_column_parse_nop(struct ovsdb_idl_row *row OVS_UNUSED,
                           const struct ovsdb_datum *datum OVS_UNUSED)
{
     /* Nothing to do */
}

static void
ovsdb_idl_column_unparse_nop(struct ovsdb_idl_row *row OVS_UNUSED)
{
     /* Nothing to do */
}

static void
ovsdb_idl_column_class_init(struct ovsdb_idl_column *column,
                            const struct ovsdb_column *column_schema,
                            const struct ovsdb_idl_column *default_column)
{
    if (default_column) {
        ovsdb_type_clone(&column->type, &default_column->type);
        column->mutable = default_column->mutable;
        column->parse = default_column->parse;
        column->unparse = default_column->unparse;;
    } else {
        ovsdb_type_clone(&column->type, &column_schema->type);
        column->mutable = column_schema->mutable;
        column->parse = ovsdb_idl_column_parse_nop;
        column->unparse = ovsdb_idl_column_unparse_nop;
    }

    column->name = xstrdup(column_schema->name);
}

static void
row_init(struct ovsdb_idl_row *row)
{
    memset(row, 0, sizeof *row);
}

static void
ovsdb_idl_table_class_init(struct ovsdb_idl_table_class *table,
                           const struct ovsdb_table_schema *table_schema,
                           const struct ovsdb_idl_table_class *default_table)
{
    size_t n_fields;
    struct ovsdb_idl_column *columns;
    const struct shash_node **nodes;
    struct shash default_columns = SHASH_INITIALIZER(&default_columns);
    int i, n;

    if (default_table) {
        for (i = 0; i < default_table->n_columns; i++) {
            const struct ovsdb_idl_column *default_column;
            default_column = &default_table->columns[i];
            shash_add(&default_columns, default_column->name, default_column);
        }
    }

    /* 'table_schema' contains the '_uuid' and '__version', while
     * idl  compiler  generated 'default table' does not. Skip both
     * columns so that number of colums in the generated idl class
     * will match with the default.    */
    n_fields = shash_count(&table_schema->columns) - OVSDB_N_STD_COLUMNS;
    columns = xmalloc(n_fields * sizeof *columns);
    nodes = shash_sort(&table_schema->columns);
    n = 0;
    for (i = 0;  i < shash_count(&table_schema->columns); i++) {
        const struct ovsdb_column *column_schema = nodes[i]->data;
        struct ovsdb_idl_column *default_column;

        if (column_schema->index < OVSDB_N_STD_COLUMNS) {
            continue;
        }
        default_column = shash_find_data(&default_columns,
                                         column_schema->name);
        ovsdb_idl_column_class_init(&columns[n++], column_schema,
                                    default_column);
    }
    free(nodes);
    shash_destroy(&default_columns);

    table->name = xstrdup(table_schema->name);
    table->is_root = table_schema->is_root;
    table->n_columns = n_fields;
    table->columns = columns;;
    table->allocation_size = default_table ? default_table->allocation_size
                                           : sizeof (struct ovsdb_idl_row);
    table->row_init = default_table ? default_table->row_init : row_init;
}

struct ovsdb_idl_class *
ovsdb_idl_class_create(const struct ovsdb_schema *schema,
                       const struct ovsdb_idl_class *default_class)
{
    struct ovsdb_idl_class *idl_class;
    struct ovsdb_idl_table_class *tables;
    size_t n_tables; 
    struct shash_node *node;
    struct shash default_tables = SHASH_INITIALIZER(&default_tables);
    int i;

    for (i = 0; i < default_class->n_tables; i++) {
        const struct ovsdb_idl_table_class *table = &default_class->tables[i];
        shash_add(&default_tables, table->name, table);
    }

    n_tables = shash_count(&schema->tables);
    tables = xmalloc(n_tables * sizeof *idl_class->tables);

    i = 0;
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *table_schema = node->data;
        struct ovsdb_idl_table_class *default_table;

        default_table = shash_find_data(&default_tables, table_schema->name);
        ovsdb_idl_table_class_init(&tables[i++], table_schema, default_table);
    }
    shash_destroy(&default_tables);

    idl_class = xmalloc(sizeof *idl_class);
    idl_class->database = xstrdup(schema->name);
    idl_class->n_tables = n_tables;
    idl_class->tables = tables;

    return idl_class;
}

static void
ovsdb_idl_class_table_destroy(struct ovsdb_idl_table_class *table)
{
    int i;

    for (i = 0; i < table->n_columns; i++) {
        struct ovsdb_type *type;
        type = (struct ovsdb_type *)&table->columns[i].type;
        ovsdb_type_destroy(type);
        free(table->columns[i].name);
    }

    free((struct ovsdb_idl_colum *)table->columns);
    free(table->name);
}

void
ovsdb_idl_class_destroy(struct ovsdb_idl_class *idl_class)
{
    int i;

    for (i = 0; i < idl_class->n_tables; i++) {
        struct ovsdb_idl_table_class *table =
            (struct ovsdb_idl_table_class *)&idl_class->tables[i];

        ovsdb_idl_class_table_destroy(table);
    }

    free((char *)idl_class->database);
    free((struct ovsdb_idl_table_class *)idl_class->tables);
    free(idl_class);
};
