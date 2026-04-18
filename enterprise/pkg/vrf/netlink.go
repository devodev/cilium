//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package vrf

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

var errLinkNotFound = errors.New("link not found")

type netLink interface {
	linkByName(name string) (netlink.Link, error)
	linkExists(name string) (bool, error)
	linkList() ([]netlink.Link, error)
	linkAdd(link netlink.Link) error
	linkDel(link netlink.Link) error
	linkSetUp(link netlink.Link) error
	linkSetAlias(link netlink.Link, alias string) error
	linkSetMaster(child, master netlink.Link) error
	linkSetNoMaster(child netlink.Link) error
}

type nl struct{}

func (n nl) linkByName(name string) (netlink.Link, error) {
	link, err := safenetlink.LinkByName(name)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil, fmt.Errorf("%w: %w", errLinkNotFound, err)
		}
		return nil, err
	}
	return link, nil
}

func (n nl) linkExists(name string) (bool, error) {
	_, err := n.linkByName(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errLinkNotFound) {
		return false, nil
	}
	return false, err
}

func (n nl) linkList() ([]netlink.Link, error) {
	return safenetlink.LinkList()
}

func (n nl) linkAdd(link netlink.Link) error {
	return netlink.LinkAdd(link)
}

func (n nl) linkDel(link netlink.Link) error {
	return netlink.LinkDel(link)
}

func (n nl) linkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (n nl) linkSetAlias(link netlink.Link, alias string) error {
	return netlink.LinkSetAlias(link, alias)
}

func (n nl) linkSetMaster(child, master netlink.Link) error {
	return netlink.LinkSetMaster(child, master)
}

func (n nl) linkSetNoMaster(child netlink.Link) error {
	return netlink.LinkSetNoMaster(child)
}
