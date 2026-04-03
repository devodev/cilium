//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package datapath

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

func ensureInspectionDevice(device string) (ifIndex int, err error) {
	if device == "" {
		return 0, fmt.Errorf("inspection device name is empty")
	}

	link, err := safenetlink.LinkByName(device)
	if err != nil {
		if err := netlink.LinkAdd(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{Name: device},
		}); err != nil {
			return 0, fmt.Errorf("failed creating inspection device %s: %w", device, err)
		}

		link, err = safenetlink.LinkByName(device)
		if err != nil {
			return 0, fmt.Errorf("failed retrieving inspection device %s: %w", device, err)
		}
	}

	if _, ok := link.(*netlink.Dummy); !ok {
		return 0, fmt.Errorf("inspection device %s already exists and is not a dummy device", device)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("failed setting inspection device %s up: %w", device, err)
	}

	return link.Attrs().Index, nil
}

func removeInspectionDevice(device string) error {
	if device == "" {
		return nil
	}

	link, err := safenetlink.LinkByName(device)
	if err != nil {
		return nil
	}
	if _, ok := link.(*netlink.Dummy); !ok {
		return fmt.Errorf("refusing to remove non-dummy inspection device %s", device)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed removing inspection device %s: %w", device, err)
	}
	return nil
}
