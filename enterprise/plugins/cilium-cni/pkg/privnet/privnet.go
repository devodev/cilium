// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	enterpriseModels "github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/client"
	privnetTypes "github.com/cilium/cilium/enterprise/pkg/privnet/types"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type addHooks struct {
	// Set in OnConfigReady
	ceeClient      *client.EnterpriseClient
	privNetEnabled bool
	cniCfg         CNIConfig
	cniArgs        *types.ArgsSpec
	ifname         string
	daemonConf     *models.DaemonConfigurationStatus

	// Set in OnIPAMReady
	ipam *models.IPAMResponse

	// Set in OnLinkConfigReady
	privNetAddressing *enterpriseModels.PrivateNetworkAddressing
}

func NewAddHooks() *addHooks {
	return &addHooks{}
}

func (h *addHooks) OnConfigReady(args *skel.CmdArgs, cniArgs *types.ArgsSpec, conf *models.DaemonConfigurationStatus) error {
	ceeClient, err := client.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("unable to create enterprise API client: %w", err)
	}

	config, err := ceeClient.EnterpriseConfig()
	if err != nil {
		return fmt.Errorf("unable to get enterprise configuration: %w", err)
	}

	cniCfg, err := h.parseCNIConfig(args.StdinData)
	if err != nil {
		return fmt.Errorf("unable to parse private networks CNI configuration: %w", err)
	}

	var enabled = config.PrivateNetworks != nil && config.PrivateNetworks.Enabled
	if err := cniCfg.Validate(enabled); err != nil {
		return fmt.Errorf("invalid private networks CNI configuration: %w", err)
	}

	// Store for later callbacks
	h.ceeClient = ceeClient
	h.privNetEnabled = enabled
	h.cniCfg = cniCfg
	h.cniArgs = cniArgs
	h.ifname = args.IfName
	h.daemonConf = conf

	return nil
}

func (h *addHooks) parseCNIConfig(data []byte) (CNIConfig, error) {
	var out struct {
		Conf CNIConfig `json:"private-networks"`
	}

	err := json.Unmarshal(data, &out)
	return out.Conf, err
}

func (h *addHooks) OnIPAMReady(ipam *models.IPAMResponse) error {
	// Store for later callbacks
	h.ipam = ipam

	return nil
}

func (h *addHooks) OnLinkConfigReady(linkConfig *connector.LinkConfig) error {
	// privnet not enabled, don't modify
	if !h.privNetEnabled || h.cniArgs == nil || h.daemonConf == nil {
		return nil
	}

	privNetAddressing, err := h.ceeClient.PrivateNetworkAddressing(
		h.cniCfg.Network, h.cniCfg.Subnet,
		string(h.cniArgs.K8S_POD_NAMESPACE),
		string(h.cniArgs.K8S_POD_NAME),
		string(h.cniArgs.K8S_POD_UID),
		h.ifname,
	)
	if err != nil {
		return fmt.Errorf("unable to determine private network: %w", err)
	}

	// Store for later callbacks
	h.privNetAddressing = privNetAddressing.Addressing

	// Modify passed LinkConfig
	if h.privNetAddressing != nil && h.privNetAddressing.Network != "" {
		// MTU for privnet enabled pods should be set on pod/lxc devices instead of default route
		// inside the pod. As address configured is not necessarily /32 or /128, so traffic will
		// exit without using default route where MTU is typically set.
		linkConfig.DeviceMTU = int(h.daemonConf.RouteMTU)
	}

	return nil
}

func (h *addHooks) OnInterfaceConfigReady(state *cmd.CmdState, ep *models.EndpointChangeRequest, res *cniTypesV1.Result) error {
	// privnet not enabled or not a privnet-attached endpoint, don't modify
	if !h.privNetEnabled || h.privNetAddressing == nil || h.privNetAddressing.Network == "" || h.ipam == nil {
		return nil
	}

	// Remove the `default via cilium_host` route installed by prepareIPs before the callback.
	// After this, `state` should only contain IPs and routes in the inner network,
	*state = cmd.CmdState{}
	res.Routes = nil

	ipv4Enabled := cmd.IPv4IsEnabled(h.ipam)
	ipv6Enabled := cmd.IPv6IsEnabled(h.ipam)

	for _, r := range h.privNetAddressing.Routes {
		dstIP, dstPrefix, err := net.ParseCIDR(r.Destination)
		if err != nil {
			return fmt.Errorf("invalid route destination %q: %w", r.Destination, err)
		}

		rte := route.Route{
			Prefix: *dstPrefix,
			MTU:    int(h.daemonConf.RouteMTU),
		}

		if r.Gateway != "" {
			gwIP := net.ParseIP(r.Gateway)
			if gwIP == nil {
				return fmt.Errorf("invalid route gateway %q", r.Gateway)
			}

			rte.Nexthop = &gwIP
		}

		switch {
		case ipv4Enabled && dstIP.To4() != nil:
			state.IP4routes = append(state.IP4routes, rte)
		case ipv6Enabled && dstIP.To4() == nil:
			state.IP6routes = append(state.IP6routes, rte)
		}
	}

	if ep.Properties == nil {
		ep.Properties = map[string]any{}
	}
	if h.privNetAddressing.Subnet == "" {
		return errors.New("private network subnet is required")
	}
	ep.Properties[privnetTypes.PropertyPrivNetNetwork] = h.privNetAddressing.Network
	ep.Properties[privnetTypes.PropertyPrivNetSubnet] = h.privNetAddressing.Subnet
	ep.Properties[privnetTypes.PropertyPrivNetNICIndex] = strconv.FormatInt(
		ptr.Deref(h.privNetAddressing.NicIndex, 0), 10)

	// TODO: Should we allow this kind of label to be set via API or should it be treated like `reserved` labels
	// and be set by the daemon on endpoint creation?
	lbl := labels.NewLabel(privnetTypes.CNINetworkNameLabel, h.privNetAddressing.Network, labels.LabelSourceCNI)
	ep.Labels = append(ep.Labels, lbl.String())

	if ipv4Enabled && h.daemonConf.Addressing.IPv4 != nil {
		if h.privNetAddressing.Address.IPv4 != "" {
			netIPv4, err := netip.ParseAddr(h.privNetAddressing.Address.IPv4)
			if err != nil {
				return fmt.Errorf("unable to parse private network IPv4 address: %w", err)
			}
			state.IP4 = netIPv4
			ep.Properties[privnetTypes.PropertyPrivNetIPv4] = h.privNetAddressing.Address.IPv4
			ep.Properties[privnetTypes.PropertyPrivNetIPv4UsesDHCP] = netIPv4.IsUnspecified()
		} else {
			// Set IPAM response to be empty - the OSS CNI plugin will use it to check if IPv4 is enabled
			h.ipam.Address.IPv4 = ""
		}
	}

	if ipv6Enabled && h.daemonConf.Addressing.IPv6 != nil {

		if h.privNetAddressing.Address.IPv6 != "" {
			netIPv6, err := netip.ParseAddr(h.privNetAddressing.Address.IPv6)
			if err != nil {
				return fmt.Errorf("unable to parse private network IPv6 address: %w", err)
			}
			state.IP6 = netIPv6
			ep.Properties[privnetTypes.PropertyPrivNetIPv6] = h.privNetAddressing.Address.IPv6
		} else {
			// Set IPAM response to be empty - the OSS CNI plugin will use it to check if IPv6 is enabled
			h.ipam.Address.IPv6 = ""
		}
	}

	if h.privNetAddressing.Mac != "" {
		ep.Mac = h.privNetAddressing.Mac
	}

	if !h.privNetAddressing.ActivatedAt.IsZero() {
		ep.Properties[privnetTypes.PropertyPrivNetActivatedAt] = h.privNetAddressing.ActivatedAt
	}

	// Disable the configuration of the legacy endpoint identifiers for secondary interfaces,
	// to prevent conflicts as they would not be unique in case of multi-NIC pods.
	if h.ifname != "eth0" {
		ep.IsSecondaryInterface = true
	}

	return nil
}

type CNIConfig struct {
	Network string `json:"network"`
	Subnet  string `json:"subnet"`
}

func (c CNIConfig) Validate(enabled bool) error {
	switch {
	case c.Network == "" && c.Subnet == "":
		return nil
	case c.Network == "":
		return fmt.Errorf("missing network")
	case c.Subnet == "":
		return fmt.Errorf("missing subnet")
	case !enabled:
		return fmt.Errorf("private networks is not enabled")
	default:
		return nil
	}
}
