// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ilb

import "flag"

var (
	FlagAppImage     string
	FlagClientImage  string
	FlagUtilsImage   string
	FlagCoreDNSImage string
	FlagNginxImage   string
	FlagMariaDBImage string

	FlagEnsureImages bool

	FlagCleanup           bool
	FlagContinueOnFailure bool
	// maybeSysdump is only effective when this option is specified.
	FlagSysdumpOnFailure      bool
	FlagSysdumpOutputFilename string

	FlagVerbose bool

	// By default, we assume cilium-cli is in the PATH. In the CI, we may want to specify custom path.
	FlagCiliumCLIPath string

	FlagMode               string
	FlagSingleNodeIPAddr   string
	FlagSingleNodeIPv6Addr string
	FlagNetworkName        string

	FlagRun   []string
	FlagShard TestShard

	// TODO (sayboras): Remove these flags once we have feature auto-detection
	FlagUseRemoteAddress  bool
	FlagXffNumTrustedHops int
)

func ParseFlags() {
	flag.Parse()
}
