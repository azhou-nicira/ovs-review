#include <config.h>
#include "ovs-bpf-helpers.h"

int output_action(struct ovs_bpf_action_ctxt *ctxt);

SEC("ovs/output")
int
output_action(struct ovs_bpf_action_ctxt *ctxt)
{
	return ovs_bpf_helper_output(ctxt->skb, ctxt->arg0);
}

char _license[] SEC("license") = "GPL";
