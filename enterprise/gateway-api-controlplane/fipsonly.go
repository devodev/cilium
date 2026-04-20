//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// This file exists in all enterprise-specific main packages to convince the
// ./contrib/scripts/check-fipsonly.sh which is used for the OSS FIPS build
// support. This script requires us that the main package includes a fipsonly.go
// file that imports the crypto/tls/fipsonly package.
//
// For the enterprise, we have our own way of FIPS support, so don't want to
// rely on the OSS FIPS build mechanism. The script has an exclusion list
// but embedded into the script. Changing the script on enterprise is non-mindful.
// Therefore, we ended up with this file that essentially does nothing, but still
// passes the check. Whenever you introduce a new main package, you can copy this
// file.

// Only include this file if GOEXPERIMENT=boringcrypto is set. This line is
// also checked by script as well.
//go:build boringcrypto

package main

/*
// Hack to convince the check. We don't want to import the boringcrypto package
// directly, but we need this single line import.
import _ "crypto/tls/fipsonly"
*/
