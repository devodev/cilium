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
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/option"
)

const (
	symbolFromEvpn = "cil_from_evpn"
	symbolToEvpn   = "cil_to_evpn"

	evpnPrefix = "enterprise_bpf_evpn"
	evpnProg   = evpnPrefix + ".c"
	evpnObj    = evpnPrefix + ".o"

	evpnCallsMap = "cilium_calls_evpn"
)

// evpnObjects receives eBPF objects for attaching to EVPN enabled interfaces.
type evpnObjects struct {
	FromEvpn *ebpf.Program `ebpf:"cil_from_evpn"`
	ToEvpn   *ebpf.Program `ebpf:"cil_to_evpn"`
}

func (o *evpnObjects) Close() {
	_ = o.FromEvpn.Close()
	_ = o.ToEvpn.Close()
}

func replaceEvpnDatapath(ctx context.Context, logger *slog.Logger, lnc *config.Config, evpnCfg evpnConfig.Config, privnetCfg privnetConfig.Config) error {
	device, err := safenetlink.LinkByName(evpnCfg.VxlanDevice)
	if err != nil {
		return fmt.Errorf("failed to retrieve link for interface %s: %w", evpnCfg.VxlanDevice, err)
	}

	if err := loader.CompileWithOptions(ctx, logger, evpnProg, evpnObj, nil); err != nil {
		return fmt.Errorf("compiling evpn program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(evpnObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", evpnObj, err)
	}

	var obj evpnObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: []any{
			config.EvpnBase(lnc, device),
			config.EvpnEnterprise(lnc, evpnCfg, privnetCfg),
		},
		MapRenames: []map[string]string{
			{
				"cilium_calls": evpnCallsMap,
			},
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	linkDir := loader.BPFFSDeviceLinksDir(bpf.CiliumPath(), device)
	if err := loader.AttachSKBProgram(logger, device, obj.FromEvpn, symbolFromEvpn,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}
	if err := loader.AttachSKBProgram(logger, device, obj.ToEvpn, symbolToEvpn,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", device, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

func cleanupEvpnDatapath(vxlanDevice string) (err error) {
	if vxlanDevice != "" {
		if link, linkErr := safenetlink.LinkByName(vxlanDevice); linkErr == nil {
			err = bpf.Remove(loader.BPFFSDeviceLinksDir(bpf.CiliumPath(), link))
		}
	}
	return errors.Join(err, loader.CleanCallsMaps(evpnCallsMap))
}
