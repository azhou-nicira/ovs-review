# Copyright (C) 2015 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

if LINUX
sbin_PROGRAMS += bpf/ovs-actions.bpf


EXTRA_DIST += $(srcdir)/bpf/ovs-bpf-helpers.h \
	      $(srcdir)/bpf/bpf-shared.h \
	      $(srcdir)/bpf/ovs-actions.c

DEP_FILES  = $(srcdir)/bpf/ovs-bpf-helpers.h \
	     $(srcdir)/bpf/bpf-shared.h \
             $(srcdir)/datapath/linux/compat/include/linux/openvswitch.h

BPF_INCLUDES=-I. -I$(srcdir)/datapath/linux/compat/include -I/usr/include

bpf/ovs-actions.bpf: $(srcdir)/bpf/ovs-actions.c $(DEP_FILES)
	$(AM_V_GEN)clang -DHAVE_CONFIG_H $(BPF_INCLUDES) $(NOSTDINC_FLAGS) \
		$(AM_CFLAGS) $(EXTRA_CFLAGS) -Wno-unused-value -Wno-pointer-sign \
		-O2 -emit-llvm -c $< -o -| $(LLC) -filetype=obj -o $@

endif
