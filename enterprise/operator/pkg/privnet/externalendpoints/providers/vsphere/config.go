//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vsphere

import (
	"fmt"

	"github.com/vmware/govmomi/property"

	"github.com/cilium/cilium/pkg/time"
)

const (
	defaultPollInterval = 30 * time.Second
)

type Config struct {
	CredentialsSecretName string           `yaml:"credentials-secret-name"`
	DataCenter            string           `yaml:"data-center"`
	RootFolder            string           `yaml:"root-folder"`
	PollInterval          time.Duration    `yaml:"poll-interval"`
	PropertyFilter        []property.Match `yaml:"property-filter"`
}

func (c *Config) SetDefaults() error {
	if c.CredentialsSecretName == "" {
		return fmt.Errorf("credentials-secret-name must be set")
	}

	if len(c.PropertyFilter) > 1 {
		return fmt.Errorf("more than one property filter is currently not supported")
	}

	if c.PollInterval == 0 {
		c.PollInterval = defaultPollInterval
	}

	return nil
}
