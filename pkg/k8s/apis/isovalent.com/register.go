// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isovalentcom

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = "isovalent.com"

	// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster.
	//
	// Maintainers: Run ./Documentation/check-crd-compat-table.sh for each release
	// Developers: Bump patch for each change in the CRD schema.
	CustomResourceDefinitionSchemaVersion = "1.30.36"

	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = "com.isovalent.k8s.crd.schema.version"
)
