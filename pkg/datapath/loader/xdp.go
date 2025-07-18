// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/datapath/xdp"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func xdpConfigModeToFlag(xdpMode xdp.Mode) link.XDPAttachFlags {
	switch xdpMode {
	case xdp.ModeLinkDriver:
		return link.XDPDriverMode
	case xdp.ModeLinkGeneric:
		return link.XDPGenericMode
	}
	return 0
}

// These constant values are returned by the kernel when querying the XDP program attach mode.
// Important: they differ from constants that are used when attaching an XDP program to a netlink device.
const (
	xdpAttachedNone uint32 = iota
	xdpAttachedDriver
	xdpAttachedGeneric
)

// xdpAttachedModeToFlag maps the attach mode that is returned in the metadata when
// querying netlink devices to the attach flags that were used to configure the
// xdp program attachement.
func xdpAttachedModeToFlag(mode uint32) link.XDPAttachFlags {
	switch mode {
	case xdpAttachedDriver:
		return link.XDPDriverMode
	case xdpAttachedGeneric:
		return link.XDPGenericMode
	}
	return 0
}

// maybeUnloadObsoleteXDPPrograms removes bpf_xdp.o from previously used
// devices.
//
// bpffsBase is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func maybeUnloadObsoleteXDPPrograms(logger *slog.Logger, xdpDevs []string, xdpMode xdp.Mode, bpffsBase string) {
	links, err := safenetlink.LinkList()
	if err != nil {
		logger.Warn("Failed to list links for XDP unload",
			logfields.Error, err,
		)
	}

	for _, link := range links {
		linkxdp := link.Attrs().Xdp
		if linkxdp == nil || !linkxdp.Attached {
			// No XDP program is attached
			continue
		}
		if strings.Contains(link.Attrs().Name, "cilium") {
			// Ignore devices created by cilium-agent
			continue
		}

		used := false
		for _, xdpDev := range xdpDevs {
			if link.Attrs().Name == xdpDev &&
				xdpAttachedModeToFlag(linkxdp.AttachMode) == xdpConfigModeToFlag(xdpMode) {
				// XDP mode matches; don't unload, otherwise we might introduce
				// intermittent connectivity problems
				used = true
				break
			}
		}
		if !used {
			if err := DetachXDP(link.Attrs().Name, bpffsBase, symbolFromHostNetdevXDP); err != nil {
				logger.Warn("Failed to detach obsolete XDP program",
					logfields.Error, err,
				)
			}
		}
	}
}

// xdpCompileArgs derives compile arguments for bpf_xdp.c.
func xdpCompileArgs(extraCArgs []string) ([]string, error) {
	args := []string{}
	copy(args, extraCArgs)

	return args, nil
}

// compileAndLoadXDPProg compiles bpf_xdp.c for the given XDP device and loads it.
func compileAndLoadXDPProg(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, xdpDev string, xdpMode xdp.Mode, extraCArgs []string) error {
	args, err := xdpCompileArgs(extraCArgs)
	if err != nil {
		return fmt.Errorf("failed to derive XDP compile extra args: %w", err)
	}

	dirs := &directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  option.Config.StateDir,
		State:   option.Config.StateDir,
	}
	prog := &progInfo{
		Source:     xdpProg,
		Output:     xdpObj,
		OutputType: outputObject,
		Options:    args,
	}

	objPath, err := compile(ctx, logger, prog, dirs)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	iface, err := safenetlink.LinkByName(xdpDev)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", xdpDev, err)
	}

	spec, err := bpf.LoadCollectionSpec(logger, objPath)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", objPath, err)
	}

	cfg := config.NewBPFXDP(nodeConfig(lnc))
	cfg.InterfaceIfindex = uint32(iface.Attrs().Index)
	cfg.DeviceMTU = uint16(iface.Attrs().MTU)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols

	var obj xdpObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: cfg,
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_xdp_%d", iface.Attrs().Index),
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	if err := attachXDPProgram(logger, iface, obj.Entrypoint, symbolFromHostNetdevXDP,
		bpffsDeviceLinksDir(bpf.CiliumPath(), iface), xdpConfigModeToFlag(xdpMode)); err != nil {
		return fmt.Errorf("interface %s: %w", xdpDev, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

// attachXDPProgram attaches prog with the given progName to link.
//
// bpffsDir should exist and point to the links/ subdirectory in the per-device
// bpffs directory.
func attachXDPProgram(logger *slog.Logger, iface netlink.Link, prog *ebpf.Program, progName, bpffsDir string, flags link.XDPAttachFlags) error {
	if prog == nil {
		return fmt.Errorf("program %s is nil", progName)
	}

	// Attempt to open and update an existing link.
	pin := filepath.Join(bpffsDir, progName)
	err := bpf.UpdateLink(pin, prog)
	switch {
	// Update successful, nothing left to do.
	case err == nil:
		logger.Info("Updated link for program",
			logfields.Link, pin,
			logfields.ProgName, progName,
		)

		return nil

	// Link exists, but is defunct, and needs to be recreated. The program
	// no longer gets triggered at this point and the link needs to be removed
	// to proceed.
	case errors.Is(err, unix.ENOLINK):
		if err := os.Remove(pin); err != nil {
			return fmt.Errorf("unpinning defunct link %s: %w", pin, err)
		}

		logger.Info("Unpinned defunct link for program",
			logfields.Link, pin,
			logfields.ProgName, progName,
		)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		logger.Info("No existing link found for program",
			logfields.Link, pin,
			logfields.ProgName, progName,
		)

	default:
		return fmt.Errorf("updating link %s for program %s: %w", pin, progName, err)
	}

	if err := bpf.MkdirBPF(bpffsDir); err != nil {
		return fmt.Errorf("creating bpffs link dir for xdp attachment to device %s: %w", iface.Attrs().Name, err)
	}

	// Create a new link. This will only succeed on nodes that support bpf_link
	// and don't have any XDP programs attached through netlink.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Attrs().Index,
		Flags:     flags,
	})
	if err == nil {
		defer func() {
			// The program was successfully attached using bpf_link. Closing a link
			// does not detach the program if the link is pinned.
			if err := l.Close(); err != nil {
				logger.Warn("Failed to close bpf_link for program",
					logfields.ProgName, progName,
				)
			}
		}()

		if err := l.Pin(pin); err != nil {
			return fmt.Errorf("pinning link at %s for program %s : %w", pin, progName, err)
		}

		// Successfully created and pinned bpf_link.
		logger.Info("Program attached using bpf_link",
			logfields.ProgName, progName,
		)

		return nil
	}

	// Kernels before 5.7 don't support bpf_link. In that case link.AttachXDP
	// returns ErrNotSupported.
	//
	// If the kernel supports bpf_link, but an older version of Cilium attached a
	// XDP program, link.AttachXDP will return EBUSY.
	if !errors.Is(err, unix.EBUSY) && !errors.Is(err, link.ErrNotSupported) {
		// Unrecoverable error from AttachRawLink.
		return fmt.Errorf("attaching program %s using bpf_link: %w", progName, err)
	}

	logger.Debug("Performing netlink attach for program",
		logfields.ProgName, progName,
	)

	// Omitting XDP_FLAGS_UPDATE_IF_NOEXIST equals running 'ip' with -force,
	// and will clobber any existing XDP attachment to the interface, including
	// bpf_link attachments created by a different process.
	if err := netlink.LinkSetXdpFdWithFlags(iface, prog.FD(), int(flags)); err != nil {
		return fmt.Errorf("attaching XDP program %s to interface %s using netlink: %w", progName, iface.Attrs().Name, err)
	}

	// Nothing left to do, the netlink device now holds a reference to the prog
	// the program stays active.
	logger.Info("Program was attached using netlink",
		logfields.ProgName, progName,
	)

	return nil
}

// DetachXDP removes an XDP program from a network interface. On kernels before
// 4.15, always removes the XDP program regardless of progName.
//
// bpffsBase is typically /sys/fs/bpf/cilium, but can be overridden to a tempdir
// during tests.
func DetachXDP(ifaceName string, bpffsBase, progName string) error {
	iface, err := safenetlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting link '%s' by name: %w", ifaceName, err)
	}

	pin := filepath.Join(bpffsDeviceLinksDir(bpffsBase, iface), progName)
	err = bpf.UnpinLink(pin)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// The pinned link exists, something went wrong unpinning it.
		return fmt.Errorf("unpinning XDP program using bpf_link: %w", err)
	}

	xdp := iface.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return nil
	}

	// Inspect the attached program to only remove the intended XDP program.
	id := xdp.ProgId
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return fmt.Errorf("opening XDP program id %d: %w", id, err)
	}
	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("getting XDP program info %d: %w", id, err)
	}
	// The program name returned by BPF_PROG_INFO is limited to 20 characters.
	// Treat the kernel-provided program name as a prefix that needs to match
	// against progName. Empty program names (on kernels before 4.15) will always
	// match and be removed.
	if !strings.HasPrefix(progName, info.Name) {
		return nil
	}

	// Pin doesn't exist, fall through to detaching using netlink.
	if err := netlink.LinkSetXdpFdWithFlags(iface, -1, int(link.XDPGenericMode)); err != nil {
		return fmt.Errorf("detaching generic-mode XDP program using netlink: %w", err)
	}

	if err := netlink.LinkSetXdpFdWithFlags(iface, -1, int(link.XDPDriverMode)); err != nil {
		return fmt.Errorf("detaching driver-mode XDP program using netlink: %w", err)
	}

	return nil
}
