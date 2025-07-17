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
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/externalendpoints/providers"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	pntypes "github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/shortener"
)

const (
	labelVMName = "privatenetworks.isovalent.com/vm-name"
)

type vsphereParams struct {
	cell.In

	Config           config.Config
	ProviderRegistry *providers.Registry
	SecretsManager   *providers.SecretsManager

	Logger    *slog.Logger
	JobGroup  job.Group
	Lifecycle cell.Lifecycle

	DB       *statedb.DB
	Networks statedb.Table[tables.PrivateNetwork]
}

type vsphereProvider struct {
	params vsphereParams
}

func RegisterVSphereProvider(p vsphereParams) error {
	if !p.Config.EnabledWithAutoExternalEndpoints() {
		return nil
	}

	vsphere := &vsphereProvider{
		params: p,
	}

	return p.ProviderRegistry.RegisterProvider("vsphere", vsphere)
}

func (v *vsphereProvider) NewInstance(ctx context.Context, cfg providers.Config) (providers.Instance, error) {
	var config Config
	if err := cfg.Config.Decode(&config); err != nil {
		return nil, err
	}

	if err := config.SetDefaults(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}

	return &vsphereInstance{
		config: config,
		name:   string(cfg.Name),

		secretsManager: v.params.SecretsManager,
		jobGroup:       v.params.JobGroup,
		logger:         v.params.Logger,
		lifecycle:      v.params.Lifecycle,

		managedExtEPs: make(sets.Set[string]),

		db:       v.params.DB,
		networks: v.params.Networks,

		stopFn: func(cell.HookContext) {},
	}, nil
}

type vsphereInstance struct {
	config Config
	name   string

	secretsManager *providers.SecretsManager
	jobGroup       job.Group
	lifecycle      cell.Lifecycle
	logger         *slog.Logger

	managedExtEPs sets.Set[string]
	stopFn        func(cell.HookContext)

	db       *statedb.DB
	networks statedb.Table[tables.PrivateNetwork]

	c *govmomi.Client // set in initialize job
}

func (v *vsphereInstance) Stop(ctx cell.HookContext) {
	v.stopFn(ctx)
}

// newClient configures a new govmomi client based on a K8s secret. The expected format of the secret is:
//
//	url: https://vsphere.host/sdk
//	user: username
//	password: password
//	insecureSkipVerify: <true/false>
//	cacert: <PEM>
func newClient(ctx context.Context, credentials map[string][]byte) (*govmomi.Client, error) {
	u, err := url.Parse(string(credentials["url"]))
	if err != nil {
		return nil, fmt.Errorf("error parsing 'url' credentials key: %w", err)
	}

	rawUsername := credentials["user"]
	rawPassword := credentials["password"]
	if len(rawUsername) > 0 {
		u.User = url.UserPassword(string(rawUsername), string(rawPassword))
	}

	var caBundle *x509.CertPool
	if rawCertificate, ok := credentials["cacert"]; ok {
		caBundle = x509.NewCertPool()
		block, _ := pem.Decode(rawCertificate)
		if block == nil {
			return nil, fmt.Errorf("error parsing 'cacert' credentials key: failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing 'cacert' credentials key: %w", err)
		}

		caBundle.AddCert(cert)
	}

	insecure := false
	if rawInsecure, ok := credentials["insecureSkipVerify"]; ok {
		insecure, err = strconv.ParseBool(string(rawInsecure))
		if err != nil {
			return nil, fmt.Errorf("error parsing 'insecureSkipVerify' credentials key: %w", err)
		}
	}

	soapClient := soap.NewClient(u, insecure)
	if caBundle != nil {
		soapClient.DefaultTransport().TLSClientConfig.RootCAs = caBundle
	}

	client, err := vim25.NewClient(ctx, soapClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create vsphere client: %w", err)
	}

	sm := session.NewManager(client)
	err = sm.Login(ctx, u.User)
	if err != nil {
		return nil, fmt.Errorf("failed to login to vsphere: %w", err)
	}

	return &govmomi.Client{
		Client:         client,
		SessionManager: sm,
	}, nil
}

func newContainerView(ctx context.Context, config Config, c *govmomi.Client) (*view.ContainerView, error) {
	finder := find.NewFinder(c.Client)
	dc, err := finder.DatacenterOrDefault(ctx, config.DataCenter)
	if err != nil {
		return nil, fmt.Errorf("failed to find datacenter %q: %w", config.DataCenter, err)
	}
	finder.SetDatacenter(dc)

	folder, err := finder.FolderOrDefault(ctx, config.RootFolder)
	if err != nil {
		return nil, fmt.Errorf("failed to find folder %q: %w", config.RootFolder, err)
	}

	viewManager := view.NewManager(c.Client)

	containerView, err := viewManager.CreateContainerView(ctx, folder.Reference(), []string{"VirtualMachine"}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create container view: %w", err)
	}

	return containerView, nil
}

func (v *vsphereInstance) Start(_ cell.HookContext) (stream.Observable[providers.EndpointChangeBatch], error) {
	out := make(chan providers.EndpointChangeBatch)

	v.jobGroup.Add(job.OneShot("initialize", func(ctx context.Context, health cell.Health) error {
		secret, err := v.secretsManager.WaitForSecret(ctx, v.config.CredentialsSecretName)
		if err != nil {
			return fmt.Errorf("unable to find credentials secret %q: %w", v.config.CredentialsSecretName, err)
		}

		// Wait for private networks table initialization
		_, watch := v.networks.Initialized(v.db.ReadTxn())
		select {
		case <-watch:
		case <-ctx.Done():
			return ctx.Err()
		}

		v.logger.Info("Starting vsphere instance", logfields.Name, v.name)

		// initialize new govmomi client
		v.c, err = newClient(ctx, secret)
		if err != nil {
			return err
		}

		// container view allows listing of VMs in the user-configured root folder
		folderView, err := newContainerView(ctx, v.config, v.c)
		if err != nil {
			return err
		}
		v.stopFn = func(ctx cell.HookContext) {
			folderView.Destroy(ctx)
		}

		synced := false
		trigger := job.NewTrigger()
		v.jobGroup.Add(job.Timer("fetch-vms", func(ctx context.Context) error {
			vms, err := v.fetchVMs(ctx, folderView)
			if err != nil {
				v.logger.Error("failed to fetch vms: %w", logfields.Error, err)
				return nil // re-try next poll interval
			}

			batch := v.emitChangeBatch(ctx, vms)
			if !synced {
				batch = append(batch, providers.EndpointChange{Op: providers.EndpointOpSync})
				synced = true
			}

			if len(batch) == 0 {
				return nil // nothing to emit
			}

			out <- batch
			return nil
		}, v.config.PollInterval, job.WithTrigger(trigger)))
		trigger.Trigger() // fetch vms immediately

		return nil
	}))

	return stream.FromChannel(out), nil
}

// extractNetworkNameForMAC attempts to determine the network name based on the device binding
func (v *vsphereInstance) extractNetworkNameForMAC(ctx context.Context, vm mo.VirtualMachine, mac string) string {
	for _, device := range vm.Config.Hardware.Device {
		veth, ok := device.(types.BaseVirtualEthernetCard)
		if !ok {
			continue // device is not a NIC
		}

		eth := veth.GetVirtualEthernetCard()
		if eth.MacAddress != mac {
			continue // not a match
		}

		switch b := eth.Backing.(type) {
		case *types.VirtualEthernetCardDistributedVirtualPortBackingInfo:
			var dst mo.DistributedVirtualPortgroup
			err := v.c.RetrieveOne(ctx, types.ManagedObjectReference{
				Type:  string(types.ManagedObjectTypeDistributedVirtualPortgroup),
				Value: b.Port.PortgroupKey,
			}, []string{"config.name"}, &dst)
			if err != nil {
				v.logger.Debug("failed to retrieve distributed virtual port group", logfields.Error, err)
				continue
			}
			return dst.Config.Name
		default:
			return "" // other backings not yet supported
		}
	}

	return ""
}

// remapNetworkName remaps the port group name reported by vsphere to the private
// network name configured locally.
func (v *vsphereInstance) remapNetworkName(in string) (string, error) {
	if in == "" {
		return "", errors.New("could not retrieve network name")
	}

	networks := statedb.Collect(v.networks.List(v.db.ReadTxn(),
		tables.PrivateNetworksByProviderAndID(tables.ProviderNameVSphere, in)))

	switch len(networks) {
	case 0:
		return "", fmt.Errorf("no private network matching %q", in)
	case 1:
		return string(networks[0].Name), nil
	default:
		return "", fmt.Errorf("multiple private networks match %q", in)
	}
}

// extractPrimaryIPAddresses extracts the primary IP from a NIC. NICs can have multiple IPs, which we currently don't
// support
func extractPrimaryIPAddresses(nic types.GuestNicInfo) (ipv4, ipv6 netip.Addr) {
	for _, ipAddr := range nic.IpConfig.IpAddress {
		state := types.NetIpConfigInfoIpAddressStatus(ipAddr.State)
		// skip address states which are invalid, inaccessible, duplicate, etc
		switch state {
		case types.NetIpConfigInfoIpAddressStatusDeprecated,
			types.NetIpConfigInfoIpAddressStatusDuplicate,
			types.NetIpConfigInfoIpAddressStatusInaccessible,
			types.NetIpConfigInfoIpAddressStatusTentative:
			continue
		}

		ip, _ := netip.ParseAddr(ipAddr.IpAddress)

		// Skip invalid or link local addresses.
		// This in particular also skips link local IPv6 addresses, which are always added to an interface,
		// even if there is no IPv6 connectivity on the LAN. This choice might be revisited at a later date.
		if !ip.IsValid() || ip.IsLinkLocalUnicast() {
			continue
		}

		switch {
		case ip.Is4() && !ipv4.IsValid():
			ipv4 = ip
		case ip.Is6() && !ipv6.IsValid():
			ipv6 = ip
		}

		if ipv4.IsValid() && ipv6.IsValid() {
			break // stop searching
		}
	}

	return ipv4, ipv6
}

var invalidLabelCharRegex = regexp.MustCompile(`[^a-zA-Z0-9-._]`)

const invalidStartEndChars = "-._"

func k8sResourceName(s string) string {
	sanitized := shortener.ShortenK8sResourceName(invalidLabelCharRegex.ReplaceAllString(s, ""))
	sanitized = strings.Trim(sanitized, invalidStartEndChars)
	return sanitized
}

func endpointName(moRef string, mac string) string {
	return k8sResourceName(fmt.Sprintf("%s-%s", moRef, mac))
}

func (v *vsphereInstance) emitChangeBatch(ctx context.Context, vms []mo.VirtualMachine) providers.EndpointChangeBatch {
	epNamespace := k8sResourceName(v.name)
	batch := make(providers.EndpointChangeBatch, 0, len(vms))
	newManagedEPs := make(sets.Set[string], len(vms))

	// create one external endpoint per network interface
	for _, vm := range vms {
		for _, nic := range vm.Guest.Net {
			if !nic.Connected {
				continue
			}

			mac, err := mac.ParseMAC(nic.MacAddress)
			if err != nil {
				v.logger.Warn("VM with invalid MAC address",
					logfields.Name, vm.Name,
					logfields.MACAddr, nic.MacAddress,
					logfields.Error, err,
				)
				continue
			}

			epName := endpointName(vm.Self.Value, nic.MacAddress)
			ipv4, ipv6 := extractPrimaryIPAddresses(nic)
			if !ipv4.IsValid() && !ipv6.IsValid() {
				continue // skip nics without valid IPs
			}

			network := nic.Network
			if network == "" {
				network = v.extractNetworkNameForMAC(ctx, vm, nic.MacAddress)
			}

			network, err = v.remapNetworkName(network)
			if err != nil {
				v.logger.Warn("Unable to determine network of VM",
					logfields.Name, vm.Name,
					logfields.MACAddr, nic.MacAddress,
					logfields.Error, err,
				)
				continue
			}

			batch = append(batch, providers.EndpointChange{
				Op:        providers.EndpointOpUpsert,
				Name:      epName,
				Namespace: epNamespace,
				Properties: &pntypes.EndpointProperties{
					Network: network,
					MAC:     mac,
					IPv4:    ipv4,
					IPv6:    ipv6,
					Labels: map[string]string{
						labelVMName: k8sResourceName(vm.Name),
					},
				},
			})
			newManagedEPs.Insert(epName)
		}
	}

	// check which VMs no longer are in the live set and emit delete notifications for them
	oldManagedEPs := v.managedExtEPs
	for oldEP := range oldManagedEPs {
		if newManagedEPs.Has(oldEP) {
			continue // still alive
		}
		batch = append(batch, providers.EndpointChange{
			Op:        providers.EndpointOpDelete,
			Name:      oldEP,
			Namespace: epNamespace,
		})

	}
	v.managedExtEPs = newManagedEPs

	return batch
}

func (v *vsphereInstance) fetchVMs(ctx context.Context, folderView *view.ContainerView) (vms []mo.VirtualMachine, err error) {
	properties := []string{"name", "guest.net", "config.hardware.device"}

	// use user-defined filter as base
	filter := property.Match{}
	if len(v.config.PropertyFilter) > 0 {
		filter = v.config.PropertyFilter[0]
	}

	// Only consider poweredOn non-template VMs. In addition, we also skip VMs without any IP
	filter["config.template"] = false
	filter["runtime.powerState"] = "poweredOn"
	if _, hasIPFilter := filter["guest.ipAddress"]; !hasIPFilter {
		filter["guest.ipAddress"] = "*"
	}

	err = folderView.RetrieveWithFilter(ctx, []string{"VirtualMachine"}, properties, &vms, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VMs: %w", err)
	}

	return vms, nil
}
