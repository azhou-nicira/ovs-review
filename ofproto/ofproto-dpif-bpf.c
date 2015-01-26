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

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <pthread.h>
#include "simap.h"
#include "util.h"
#include "dirs.h"
#include "unixctl.h"
#include "dynamic-string.h"
#include "ovs-atomic.h"
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"
#include "ofproto-dpif-bpf.h"
#include "libbpf.h"
#include "bpf/bpf-shared.h"

#define DEFAULT_BPF_ACTION_FILE "ovs-actions.bpf"
#define BPF_MAP_STUB_SIZE 32

VLOG_DEFINE_THIS_MODULE(bpf);

struct bpf_info {
    struct simap bpf_maps;
    struct simap bpf_progs;
};

static struct bpf_info ovs_bpfs__ = {
    SIMAP_INITIALIZER(&ovs_bpfs__.bpf_maps),
    SIMAP_INITIALIZER(&ovs_bpfs__.bpf_progs),
};

static bool bpf_enable__ = false;
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct bpf_info *const ovs_bpfs OVS_GUARDED_BY(mutex) = &ovs_bpfs__;

#define BPF_UNIXCTL_CHECK(conn) \
    if (bpf_unixctl_check_enable(conn) == -1) return

/*
 * Get the default eBPF action file name.
 *
 * Returns the file name. Caller is responsible for free the memory.  */
static char *
bpf_default_path(void)
{
    return xasprintf("%s/%s", ovs_pkgdatadir(), DEFAULT_BPF_ACTION_FILE);
}

static int
bpf_unixctl_check_enable(struct unixctl_conn *conn)
{
    if (!bpf_enable__) {
        unixctl_command_reply(conn, "Current datapath doest not support eBPF actions.\n");
        return -1;
    }

    return 0;
}

static void 
add_map(char *map_name,  int fd)
{
    ovs_mutex_lock(&mutex);
    simap_put(&ovs_bpfs->bpf_maps, map_name, fd);
    ovs_mutex_unlock(&mutex);
}

static void
add_prog(char *prog_name, int fd)
{
    ovs_mutex_lock(&mutex);
    simap_put(&ovs_bpfs->bpf_progs, prog_name, fd);
    ovs_mutex_unlock(&mutex);
}

static int
is_ovs_section(const char *shname) {
   return !memcmp(shname, "ovs", 3);
}

static int
load_maps(struct bpf_map_def *maps, int len, int map_fds[])
{
    int i, fd;

    for (i = 0; i < len / sizeof(struct bpf_map_def); i++) {
        char *name;

        fd = bpf_create_map(maps[i].type, maps[i].key_size,
                            maps[i].value_size, maps[i].max_entries);

        if (fd < 0) {
            return fd;
        }

        name = xasprintf("map%d(type[%u],ks[%u],vs[%u],max[%u])",
                         i, maps[i].type, maps[i].key_size,
                         maps[i].value_size, maps[i].max_entries);

        map_fds[i] = fd;
        add_map(name, fd);
        free(name);
    }

    return 0;
}

static int
load_prog(int type, struct bpf_insn *prog, int size, char *license)
{
    return bpf_prog_load(type, prog, size, license);
}

static int
parse_relo_and_apply(Elf_Data *data, Elf_Data *symbols,
                     GElf_Shdr *shdr, struct bpf_insn *insn, int map_fds[])
{
    int i, nrels;

    nrels = shdr->sh_size / shdr->sh_entsize;

    for (i = 0; i < nrels; i++) {
        GElf_Sym sym;
        GElf_Rel rel;
        unsigned int insn_idx;

        gelf_getrel(data, i, &rel);

        insn_idx = rel.r_offset / sizeof(struct bpf_insn);

        gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

        if (insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
            VLOG_ERR("invalid relo for insn[%d].code 0x%x\n",
                     insn_idx, insn[insn_idx].code);
            return 1;
        }
        insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
        insn[insn_idx].imm = map_fds[sym.st_value / sizeof(struct bpf_map_def)];
    }

    return 0;
}

static int
get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
        GElf_Shdr *shdr, Elf_Data **data)
{
    Elf_Scn *scn;

    scn = elf_getscn(elf, i);
    if (!scn) {
        return -1;
    }

    if (gelf_getshdr(scn, shdr) != shdr) {
        return -2;
    }

    *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
    if (!*shname || !shdr->sh_size) {
        return -3;
    }

    *data = elf_getdata(scn, 0);
    if (!*data || elf_getdata(scn, *data) != NULL) {
        return -4;
    }

    return 0;
}

static int
ofproto_dpif_load_bpf(const char *bpf_file OVS_UNUSED)
{
    int fd, i;
    Elf *elf;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr, shdr_prog;
    Elf_Data *data, *data_prog, *symbols;
    char *shname, *shname_prog, *license, *err;
    int *map_fds;

    err = license = NULL;
    symbols = NULL;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        err = xasprintf("Elf library out of date");
        goto error;
    }

    fd = open(bpf_file, O_RDONLY, 0);
    if (fd < 0) {
        err = xasprintf("Failed to read %s", bpf_file);
        goto error;
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        err = xasprintf("Elf file %s has internal error", bpf_file);
        goto error;
    }

    
    if (gelf_getehdr(elf, &ehdr) != &ehdr) {
        err = xasprintf("Elf file %s has internal error", bpf_file);
        goto error;
    }

    map_fds = xmalloc(sizeof(int) * ehdr.e_shnum);
    for (i = 1;  i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data)) {
            continue;
        }

        if ((strcmp(shname, "license") == 0) && (license == NULL)) {
            license = xmalloc(data->d_size);
            memcpy(license, data->d_buf, data->d_size);
        } else if (strcmp(shname, "maps") == 0) {
            if (load_maps(data->d_buf, data->d_size, map_fds)) {
                err = xasprintf("Failed to load maps");
                goto error;
            }
        } else if (shdr.sh_type == SHT_SYMTAB) {
            symbols = data;
        }
    }

    /* Load programs that need map fixups (relocations).  */
    for (i = 1;  i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data)) {
            continue;
        }

        if (shdr.sh_type == SHT_REL) {
            struct bpf_insn *insns;

            if (get_sec(elf, shdr.sh_info, &ehdr, &shname_prog,
                        &shdr_prog, &data_prog)) {
                continue;
            }

            insns = (struct bpf_insn *) data_prog->d_buf;
            
            if (is_ovs_section(shname_prog)) {
                int fd;
                if (parse_relo_and_apply(data, symbols, &shdr, insns, map_fds)) {
                    err = xasprintf("Failed to relocate ovs programs.");
                    goto error;
                }
                fd = load_prog(BPF_PROG_TYPE_OPENVSWITCH, insns,
                               data_prog->d_size, license);

                if (fd) {
                    add_prog(shname_prog, fd);
                } else {
                    err = xasprintf("Failed load ovs program %s", shname_prog);
                    goto error;
                }
            }
        }
    }
    free(map_fds);
    map_fds = NULL;

    /* Load OVS programs that don't use maps. */
    for (i = 1;  i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data)) {
            continue;
        }

        if (is_ovs_section(shname) && !ofproto_dpif_bpf_lookup(shname)) {
            int fd;

            fd = load_prog(BPF_PROG_TYPE_OPENVSWITCH, data->d_buf,
                           data->d_size, license);

            if (fd) {
                add_prog(shname, fd);
            } else {
                err = xasprintf("Failed load ovs program %s", shname);
                goto error;
            }
        }
    }

error:
    if (fd) {
        close(fd);
    }

    if (license) {
        free(license);
    }

    if (map_fds) {
        free(map_fds);
    }

    if (err) {
        VLOG_ERR("%s", err); 
        free(err);
        return -1;
    }

    return 0;
}

void
ofproto_dpif_bpf_close()
{
    struct simap_node *node;

    ovs_mutex_lock(&mutex);

    SIMAP_FOR_EACH(node, &ovs_bpfs->bpf_progs) {
        //int fd = (int)node->data;

        //fclose(fd);
        simap_delete(&ovs_bpfs->bpf_progs, node);
    }

    SIMAP_FOR_EACH(node, &ovs_bpfs->bpf_maps) {
        //int fd = (int)node->data;
        //fclose(fd);
        simap_delete(&ovs_bpfs->bpf_maps, node);
    }

    ovs_mutex_unlock(&mutex);
}

int
ofproto_dpif_bpf_lookup(const char *bpf_prog_name)
{
    struct simap_node *node;
    int fd = 0;

    ovs_mutex_lock(&mutex);
    node = simap_find(&ovs_bpfs->bpf_progs, bpf_prog_name);
    if (node) {
        fd =(int)node->data;
    }
    ovs_mutex_unlock(&mutex);

    return fd;
}

static void
bpf_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct simap_node *node;
    char *bpf_file;

    BPF_UNIXCTL_CHECK(conn);

    bpf_file = bpf_default_path();
    ds_put_format(&ds, "eBPF file: %s \n", bpf_file);
    free(bpf_file);

    ovs_mutex_lock(&mutex);

    ds_put_format(&ds, "eBPF maps:\n");
    SIMAP_FOR_EACH(node, &ovs_bpfs->bpf_maps) {
        ds_put_format(&ds, "\t%-40s%d\n", node->name, (int)node->data);
    }

    ds_put_format(&ds, "eBPF programs:\n");
    SIMAP_FOR_EACH(node, &ovs_bpfs->bpf_progs) {
        ds_put_format(&ds, "\t%-40s%d\n", node->name, (int)node->data);
    }

    ovs_mutex_unlock(&mutex);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bpf_unixctl_clear(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    BPF_UNIXCTL_CHECK(conn);

    ofproto_dpif_bpf_close();
    unixctl_command_reply(conn, "OK");
}

static void
bpf_unixctl_reload(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    char *bpf_fpath = NULL;
    int err = 0;

    BPF_UNIXCTL_CHECK(conn);

    ofproto_dpif_bpf_close();

    bpf_fpath = bpf_default_path();
    err = ofproto_dpif_load_bpf(bpf_fpath);
    free(bpf_fpath);
    unixctl_command_reply(conn, err ? "Failed" : "OK");
}

int
ofproto_dpif_bpf_init(bool enable)
{
    char *bpf_fpath = NULL;
    int err = 0;

    bpf_enable__ = enable;

    unixctl_command_register("bpf/show",  "", 0, 0, bpf_unixctl_show, NULL);
    unixctl_command_register("bpf/clear", "", 0, 0, bpf_unixctl_clear, NULL);
    unixctl_command_register("bpf/reload","", 1, 1, bpf_unixctl_reload, NULL);

    err = 0;
    if (enable) {
        bpf_fpath = bpf_default_path();
        err = ofproto_dpif_load_bpf(bpf_fpath);
        free(bpf_fpath);
    }

    return err;
}
