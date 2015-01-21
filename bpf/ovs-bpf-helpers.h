#ifndef __OVS_BPF_HELPERS_H
#define __OVS_BPF_HELPERS_H

#include <stdint.h>
#include <linux/openvswitch.h>
struct sk_buff;

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) OVS_BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) OVS_BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) OVS_BPF_FUNC_map_delete_elem;
static int (*ovs_bpf_helper_output)(struct sk_buff *skb, uint32_t out_port) =
	(void *) OVS_BPF_FUNC_output;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#endif
