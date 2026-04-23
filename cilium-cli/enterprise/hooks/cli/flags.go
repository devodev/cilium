// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cli

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/pkg/option"
)

func addCommonJUnitFlags(flags *pflag.FlagSet, params *check.EnterpriseJUnitParams) {
	flags.StringVar(&params.JunitFile, "junit-file", "", "Generate junit report and write to file")
	flags.Var(option.NewMapOptions(&params.JunitProperties), "junit-property", "Add key=value properties to the generated junit file")
	flags.StringSliceVar(&params.CodeOwners, "code-owners", []string{}, "Use the code owners defined in these files for --log-code-owners")
	flags.MarkHidden("code-owners")
	flags.BoolVar(&params.LogCodeOwners, "log-code-owners", false, "Log code owners for tests that fail")
	flags.MarkHidden("log-code-owners")
	flags.StringSliceVar(&params.ExcludeCodeOwners, "exclude-code-owners", []string{}, "Exclude specific code owners from --log-code-owners")
	flags.MarkHidden("exclude-code-owners")
}
