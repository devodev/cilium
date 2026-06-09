//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package api

import "maps"

func init() {
	var enterpriseSourceFileNames = map[uint8]string{
		// @@ source files list begin

		// enterprise source files from bpf/
		201: "enterprise_bpf_host.h",
		202: "enterprise_bpf_evpn.c",
		203: "enterprise_bpf_lxc.h",

		// header files from bpf/lib/
		220: "enterprise_evpn.h",
		221: "enterprise_privnet.h",

		// @@ source files list end
	}

	maps.Copy(files, enterpriseSourceFileNames)
}
