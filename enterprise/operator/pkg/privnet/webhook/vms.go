// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package webhook

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	admission_v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	virt_v1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/forklift"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

func newVM(in struct {
	cell.In

	Log    *slog.Logger
	Config config.Config

	DB       *statedb.DB
	NADs     statedb.Table[tables.NetworkAttachmentDefinition]
	Networks statedb.Table[tables.PrivateNetwork]

	DaemonConfig *option.DaemonConfig
	Inventory    forklift.Inventory
}) (out HandlersOut) {
	var scheme = runtime.NewScheme()
	virt_v1.AddToScheme(scheme)

	var hook = vm{
		cfg:       in.Config,
		decoder:   admission.NewDecoder(scheme),
		db:        in.DB,
		nads:      in.NADs,
		nets:      in.Networks,
		inventory: in.Inventory,
	}

	out.Handlers = append(out.Handlers,
		Handler{
			Path:    "/virtualmachines/mutate",
			Handler: loggingHandler(in.Log, hook.Mutate),
		},
	)

	return out
}

type vm struct {
	cfg     config.Config
	decoder admission.Decoder

	db   *statedb.DB
	nads statedb.Table[tables.NetworkAttachmentDefinition]
	nets statedb.Table[tables.PrivateNetwork]

	inventory forklift.Inventory
}

func (v *vm) Mutate(ctx context.Context, req admission.Request) admission.Response {
	switch req.Operation {
	case admission_v1.Create:
	default:
		return admission.Allowed("Operation is not Create")
	}

	var vm virt_v1.VirtualMachine
	if err := v.decoder.DecodeRaw(req.Object, &vm); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decoding the object: %w", err))
	}

	if !forklift.IsMigratedVM(&vm) {
		return admission.Allowed("VM does not require to be patched")
	}

	if vm.Spec.Template == nil {
		// This is most likely invalid, but it is not our business to block it.
		return admission.Allowed("VM does not require to be patched")
	}

	if err := v.mutate(ctx, &vm); err != nil {
		return admission.Errored(err.StatusCode(), err.Unwrap())
	}

	marshaled, err := json.Marshal(vm)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("marshaling the patch: %w", err))
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaled)
}

func (v *vm) mutate(ctx context.Context, vm *virt_v1.VirtualMachine) *httpError {
	var secondary []types.NetworkAttachment

	// networks only contains the information about the VM networks targeting Cilium
	// and associated with a known private network, and excludes all the ones we don't
	// want to mangle with, as not managed by us.
	networks, hasPrimary, err := v.collectNetworks(vm.GetNamespace(), vm.Spec.Template.Spec.Networks)
	if err != nil {
		return newHTTPError(http.StatusBadRequest, err)
	}

	if len(networks) == 0 {
		// No network appears to be managed by us, hence let's not mangle with this VM.
		return nil
	}

	netInfo, err := v.inventory.NetworkInfoForVM(ctx, vm)
	if err != nil {
		return newHTTPError(http.StatusInternalServerError, fmt.Errorf("querying inventory: %w", err))
	}

	var annotations = vm.Spec.Template.ObjectMeta.Annotations
	if annotations == nil {
		annotations = make(map[string]string)
		vm.Spec.Template.ObjectMeta.Annotations = annotations
	}

	// Forklift does not mark any Multus network as the default one. However,
	// that means that the resulting virt-launcher pod eventually gets one
	// extra interface attached to the pod network, in addition to the Multus
	// ones. Even though only the Multus ones get then propagated to the actual
	// VM, this is still suboptimal, as it creates unnecessary endpoints, and
	// causes the primary pod IP to no longer map to an actual network IP,
	// hence breaking services and alike. Let's prevent this ensuring that the
	// network corresponding to the first interface targeting Cilium is
	// explicitly marked as the default one.
	var ifaces = vm.Spec.Template.Spec.Domain.Devices.Interfaces
	if !hasPrimary {
		for _, iface := range ifaces {
			net, ok := networks[vmNetworkName(iface.Name)]
			if ok {
				net.primary = true
				networks[vmNetworkName(iface.Name)] = net
				vm.Spec.Template.Spec.Networks[net.index].Multus.Default = true
				break
			}
		}
	}

	for idx, iface := range ifaces {
		net, ok := networks[vmNetworkName(iface.Name)]
		if !ok {
			// No network found. Either there is no matching network, in which
			// case Kubevirt will eventually reject the request, or we don't
			// want to mangle with it. This includes the pod network interface,
			// if any.
			continue
		}

		// We configure all managed interfaces to target a user-configurable
		// binding, so that we are in charge of handling DHCP. Indeed, Forklift
		// hard-codes the Pod network interface to masquerade mode, and Multus
		// ones to bridge mode, which is not the desired behavior in our context.
		ifaces[idx].InterfaceBindingMethod = virt_v1.InterfaceBindingMethod{}
		ifaces[idx].Binding = &virt_v1.PluginBinding{Name: v.cfg.NetworkBinding}

		// Forklift propagates the original MAC address to the interface, so we
		// can use it to find the mapping.
		if iface.MacAddress == "" {
			return newHTTPError(http.StatusBadRequest, fmt.Errorf("unknown MAC address for VM network %q", iface.Name))
		}

		mac, err := mac.ParseMAC(iface.MacAddress)
		if err != nil {
			return newHTTPError(http.StatusBadRequest, fmt.Errorf("parsing MAC address for VM network %q: %w", iface.Name, err))
		}

		v4, v6, err := v.lookupIPs(netInfo, mac, net.subnet.DHCP)
		if err != nil {
			return newHTTPError(http.StatusInternalServerError, fmt.Errorf("retrieving IP addresses for VM network %q: %w", iface.Name, err))
		}

		var attachment = types.NetworkAttachment{
			Network:   string(net.network),
			Subnet:    string(net.subnet.Name),
			Interface: iface.Name,

			IPv4: v4,
			IPv6: v6,
			MAC:  mac,
		}

		if net.primary {
			marshaled, err := json.MarshalIndent(attachment, "", "  ")
			if err != nil {
				return newHTTPError(http.StatusInternalServerError, fmt.Errorf("marshaling network attachment: %w", err))
			}

			annotations[types.PrivateNetworkAnnotation] = string(marshaled)
		} else {
			secondary = append(secondary, attachment)
		}
	}

	if len(secondary) > 0 {
		marshaled, err := json.MarshalIndent(secondary, "", "  ")
		if err != nil {
			return newHTTPError(http.StatusInternalServerError, fmt.Errorf("marshaling network attachments: %w", err))
		}

		annotations[types.PrivateNetworkSecondaryAttachmentsAnnotation] = string(marshaled)
	}

	return nil
}

func (v *vm) lookupIPs(netInfo forklift.NetworkInfo, mac mac.MAC, dhcp bool) (v4, v6 netip.Addr, err error) {
	// Preserve IPv4 addresses only if the users explicitly requested it,
	// or the subnet has not DHCP enabled.
	dhcp = dhcp && !netInfo.PreserveStaticIPs

	info, ok := netInfo.ByMAC(mac)
	if !ok && !dhcp {
		return v4, v6, errors.New("no entry found in inventory")
	}

	v4 = info.IPv4
	v6 = info.IPv6

	if dhcp {
		v4 = netip.IPv4Unspecified()
	}

	if !v4.IsValid() && !v6.IsValid() {
		return v4, v6, errors.New("no IP found in inventory")
	}

	return v4, v6, nil
}

type (
	vmNetworkName string
	vmNetworkMap  map[vmNetworkName]vmNetwork

	vmNetwork struct {
		name  vmNetworkName
		index uint

		// nad references the target Multus NetworkAttachmentDefinition.
		nad tables.NamespacedName

		network tables.NetworkName
		subnet  tables.PrivateNetworkSubnet

		// primary is true for a Multus network with the [Default] flag set). We do
		// not explicitly enforce that only a single network is marked as primary,
		// as that will be subsequently enforced by Kubevirt itself.
		primary bool
	}
)

func (v *vm) collectNetworks(vmns string, networks []virt_v1.Network) (nm vmNetworkMap, hasPrimary bool, err error) {
	var (
		nets = make(vmNetworkMap, len(networks))
		txn  = v.db.ReadTxn()
	)

	for idx, n := range networks {
		if n.Multus == nil {
			hasPrimary = hasPrimary || n.Pod != nil
			continue
		}

		if n.Multus.NetworkName == "" {
			return nil, false, fmt.Errorf("unspecified NAD name for VM network %q", n.Name)
		}

		ns, name, err := cache.SplitMetaNamespaceKey(n.Multus.NetworkName)
		if err != nil {
			return nil, false, fmt.Errorf("invalid NAD name for VM network %q: %w", n.Name, err)
		}

		hasPrimary = hasPrimary || n.Multus.Default
		var net = vmNetwork{
			name:  vmNetworkName(n.Name),
			index: uint(idx),
			nad: tables.NamespacedName{
				Namespace: cmp.Or(ns, vmns), Name: name,
			},
			primary: n.Multus.Default,
		}

		nad, _, found := v.nads.Get(txn, tables.NADByNamespacedName(net.nad))
		if !found {
			return nil, false, fmt.Errorf("invalid NAD %q for VM network %q: not found", net.nad.String(), n.Name)
		}

		switch {
		// The NAD does not target Cilium, hence we don't want to mangle with this network.
		case nad.CNIConfig.Type != tables.NADCNIConfigTypeCilium:
			continue
		// The NAD does target Cilium, but without specifying any private networks parameter.
		// Let's assume that users want to connect to the default pod network, and don't
		// mangle with this network.
		case nad.CNIConfig.PrivateNetworks == tables.NADCNIConfigPrivateNetworks{}:
			continue
		}

		net.network = nad.Network()
		net.subnet, err = v.lookupSubnet(txn, net.network, nad.Subnet())
		if err != nil {
			return nil, false, fmt.Errorf("invalid NAD %q for VM network %q: %w", net.nad.String(), n.Name, err)
		}

		net.primary = n.Multus.Default
		nets[net.name] = net
	}

	return nets, hasPrimary, nil
}

func (v *vm) lookupSubnet(
	txn statedb.ReadTxn, network tables.NetworkName, subnet tables.SubnetName,
) (tables.PrivateNetworkSubnet, error) {
	switch {
	case network == "":
		return tables.PrivateNetworkSubnet{}, errors.New("unknown private network")
	case subnet == "":
		return tables.PrivateNetworkSubnet{}, errors.New("unknown private network subnet")
	}

	net, _, found := v.nets.Get(txn, tables.PrivateNetworkByName(network))
	if !found {
		return tables.PrivateNetworkSubnet{}, fmt.Errorf("private network %q not found", network)
	}

	idx := slices.IndexFunc(net.Subnets, func(s tables.PrivateNetworkSubnet) bool { return s.Name == subnet })
	if idx == -1 {
		return tables.PrivateNetworkSubnet{}, fmt.Errorf("subnet %q not found in private network %q", subnet, network)
	}

	return net.Subnets[idx], nil
}

type httpError struct {
	code int32
	err  error
}

func newHTTPError(code int32, err error) *httpError {
	return &httpError{code: code, err: err}
}

func (e *httpError) Error() string     { return e.err.Error() }
func (e *httpError) Unwrap() error     { return e.err }
func (e *httpError) StatusCode() int32 { return e.code }
