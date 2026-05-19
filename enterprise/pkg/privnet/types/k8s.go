//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/mac"
)

const (
	// PrivateNetworkAnnotationPrefix is the common prefix for private network annotations.
	PrivateNetworkAnnotationPrefix = "privnet.isovalent.com"

	// PrivateNetworkAnnotation is the name of the annotation to attach pods to a particular
	// private network.
	PrivateNetworkAnnotation = PrivateNetworkAnnotationPrefix + "/network-attachment"

	// PrivateNetworkSecondaryAttachmentsAnnotation is the name of the annotation to configure
	// the network attachments for secondary interfaces.
	PrivateNetworkSecondaryAttachmentsAnnotation = PrivateNetworkAnnotationPrefix + "/secondary-network-attachments"

	// PrivateNetworkInactiveAnnotationLegacy is the name of the annotation which marks the pod inactive.
	PrivateNetworkInactiveAnnotation = PrivateNetworkAnnotationPrefix + "/inactive"

	// PrivateNetworkINBAPIServerPortAnnotation is the name of the node annotation propagating
	// the TCP port the privnet API server is listening to.
	PrivateNetworkINBAPIServerPortAnnotation = PrivateNetworkAnnotationPrefix + "/inb-api-server-port"
)

// NetworkAttachment is the value of PrivateNetworkAnnotation (encoded as JSON)
type NetworkAttachment struct {
	Network   string     `json:"network"`
	Interface string     `json:"interface,omitzero"`
	Subnet    string     `json:"subnet,omitzero"`
	IPv4      netip.Addr `json:"ipv4,omitzero"`
	IPv6      netip.Addr `json:"ipv6,omitzero"`
	MAC       mac.MAC    `json:"mac,omitempty"`
}

type annotatedObject interface {
	GetLabels() map[string]string
	GetAnnotations() map[string]string
}

func HasNetworkAttachmentAnnotation(obj annotatedObject) bool {
	_, found := annotation.Get(obj, PrivateNetworkAnnotation, PrivateNetworkSecondaryAttachmentsAnnotation)
	return found
}

func ExtractNetworkAttachmentAnnotation(obj annotatedObject) (*NetworkAttachment, error) {
	raw, found := annotation.Get(obj, PrivateNetworkAnnotation)
	if !found {
		return nil, nil // not found
	}

	var primary NetworkAttachment
	err := json.Unmarshal([]byte(raw), &primary)
	if err != nil {
		return nil, fmt.Errorf("invalid value in %q annotation: %w", PrivateNetworkAnnotation, err)
	}
	primary.Interface = ""

	return &primary, nil
}

func ExtractNetworkSecondaryAttachmentsAnnotation(obj annotatedObject) ([]NetworkAttachment, error) {
	raw, found := annotation.Get(obj, PrivateNetworkSecondaryAttachmentsAnnotation)
	if !found {
		return nil, nil // not found
	}

	var secondary []NetworkAttachment
	err := json.Unmarshal([]byte(raw), &secondary)
	if err != nil {
		return nil, fmt.Errorf("invalid value in %q annotation: %w", PrivateNetworkSecondaryAttachmentsAnnotation, err)
	}

	var with, without bool
	for _, attachment := range secondary {
		with, without = with || attachment.Interface != "", without || attachment.Interface == ""
		if with && without {
			return nil, fmt.Errorf("invalid value in %q annotation: interface must be specified for either none or all secondary attachments",
				PrivateNetworkSecondaryAttachmentsAnnotation)
		}
	}

	return secondary, nil
}

func ExtractInactiveAnnotation(obj annotatedObject) (inactive bool, err error) {
	raw, found := annotation.Get(obj, PrivateNetworkInactiveAnnotation)
	if !found {
		return false, nil // not found means endpoint is active
	}

	inactive, err = strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid value in %q annotation: %w", PrivateNetworkInactiveAnnotation, err)
	}
	return inactive, nil
}
