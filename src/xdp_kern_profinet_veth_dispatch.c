// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Copyright (C) 2021-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <xdp/xdp_helpers.h>

#include "net_def.h"

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 2);
} veth_map SEC(".maps");

struct {
	__uint(priority, 10);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_sock_prog);

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_ethernet_header *veth;
	bool redirect = false;
	void *p = data;
	int if_key;

	veth = p;
	if ((void *)(veth + 1) > data_end)
		return XDP_PASS;
	p += sizeof(*veth);

	/* Check for VLAN frames */
	if (veth->vlan_proto != bpf_htons(ETH_P_8021Q))
		return XDP_PASS;

	/* Check for valid Profinet frames */
	if (veth->vlan_encapsulated_proto != bpf_htons(ETH_P_PROFINET_RT))
		return XDP_PASS;

	/* Check for VID 100 */
	if ((bpf_ntohs(veth->vlantci) & VLAN_ID_MASK) == 100) {
		if_key = 0;
		redirect = true;
	}

	/* Check for VID 200 */
	if ((bpf_ntohs(veth->vlantci) & VLAN_ID_MASK) == 200) {
		if_key = 1;
		redirect = true;
	}

	if (!redirect)
		return XDP_PASS;

	/* Redirect to veth and to container */
	if (bpf_map_lookup_elem(&veth_map, &if_key))
		return bpf_redirect_map(&veth_map, if_key, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
