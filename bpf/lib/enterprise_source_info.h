/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline int
__enterprise_id_for_file(const char *const header_name)
{
	/* @@ source files list begin */

	/* enterprise source files from bpf/ */
	_strcase_(201, "enterprise_bpf_host.h");
	_strcase_(202, "enterprise_bpf_evpn.c");
	_strcase_(203, "enterprise_bpf_lxc.h");

	/* header files from bpf/lib/ */
	_strcase_(220, "enterprise_evpn.h");
	_strcase_(221, "enterprise_privnet.h");

	/* @@ source files list end */

	return 0;
}
