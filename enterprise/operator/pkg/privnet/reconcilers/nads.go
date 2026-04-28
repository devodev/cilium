// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	nadclientv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	apiextclientv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

// CNILogsDebug is the type to determine whether NADs should be configured to emit debug logs.
type CNILogsDebug bool

// NetworkAttachmentDefinitionsCell groups the NetworkAttachmentDefinition reconciliation
// operations that need to be performed by all operator replicas. Any operation that depends
// on leader election must be configured in a separate cell.
var NetworkAttachmentDefinitionsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite NetworkAttachmentDefinitions table.
		tables.NewNetworkAttachmentDefinitionsTable,

		// Provides the ReadWrite DesiredNetworkAttachmentDefinitions table.
		tables.NewDesiredNetworkAttachmentDefinitionsTable,

		// Provides the client to interact with NetworkAttachmentDefinitions.
		newNADsClient,

		// Provides the reconciler handling NetworkAttachmentDefinitions.
		newNetworkAttachmentDefinitions,
	),

	cell.Provide(
		// Provides the ReadOnly NetworkAttachmentDefinitions table.
		statedb.RWTable[tables.NetworkAttachmentDefinition].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*NetworkAttachmentDefinitions).registerK8sReflector,
	),
)

// NetworkAttachmentDefinitionsCell groups the NetworkAttachmentDefinition reconciliation
// operations that need to be performed only by the leader operator replica.
var NetworkAttachmentDefinitionsLeaderCell = cell.Group(
	cell.ProvidePrivate(
		// Provides whether NADs should be configured to emit debug logs.
		// It is provided via hive so that it can be overridden for testing purposes.
		func(log *slog.Logger) CNILogsDebug {
			return CNILogsDebug(log.Enabled(context.TODO(), slog.LevelDebug))
		},
	),

	cell.Invoke(
		// Registers the reconciler responsible for updating the desired NADs table.
		(*NetworkAttachmentDefinitions).registerDesiredReconciler,

		// Registers the reconciler responsible for reconciling the desired NADs into Kubernetes.
		(*NetworkAttachmentDefinitions).registerK8sReconciler,
	),
)

type NetworkAttachmentDefinitions struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db         *statedb.DB
	nads       statedb.RWTable[tables.NetworkAttachmentDefinition]
	tbl        statedb.RWTable[tables.DesiredNetworkAttachmentDefinition]
	networks   statedb.Table[tables.PrivateNetwork]
	namespaces statedb.Table[daemonk8s.Namespace]

	crdcl apiextclientv1.CustomResourceDefinitionInterface
	nadcl func(string) nadclientv1.NetworkAttachmentDefinitionInterface
}

func newNetworkAttachmentDefinitions(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB         *statedb.DB
	NADs       statedb.RWTable[tables.NetworkAttachmentDefinition]
	Table      statedb.RWTable[tables.DesiredNetworkAttachmentDefinition]
	Networks   statedb.Table[tables.PrivateNetwork]
	Namespaces statedb.Table[daemonk8s.Namespace]

	Client       client.Clientset
	MultusClient nadclientv1.K8sCniCncfIoV1Interface
}) (*NetworkAttachmentDefinitions, error) {
	reconciler := &NetworkAttachmentDefinitions{
		log:        in.Log,
		jg:         in.JobGroup,
		cfg:        in.Config,
		db:         in.DB,
		nads:       in.NADs,
		tbl:        in.Table,
		networks:   in.Networks,
		namespaces: in.Namespaces,
	}

	if !in.Config.EnabledWithNADIntegration() {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() || in.MultusClient == nil {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.crdcl = in.Client.ApiextensionsV1().CustomResourceDefinitions()
	reconciler.nadcl = in.MultusClient.NetworkAttachmentDefinitions
	return reconciler, nil
}

func (n *NetworkAttachmentDefinitions) registerK8sReflector() error {
	if !n.cfg.EnabledWithNADIntegration() {
		return nil
	}

	return k8s.RegisterReflector(n.jg, n.db, k8s.ReflectorConfig[tables.NetworkAttachmentDefinition]{
		Name:          "to-table",
		Table:         n.nads,
		ListerWatcher: utils.ListerWatcherFromTyped(n.nadcl(corev1.NamespaceAll)),

		// Validate that the NetworkAttachmentDefinition CRD is actually present
		// before attempting to watch the existing instances.
		CRDSync: n.newCRDSyncPromise(),

		Transform: func(txn statedb.ReadTxn, obj any) (tables.NetworkAttachmentDefinition, bool) {
			nad, ok := obj.(*nadv1.NetworkAttachmentDefinition)
			if !ok {
				return tables.NetworkAttachmentDefinition{}, false
			}

			var cfg tables.NADCNIConfig

			// Attempt to unmarshal the core CNI fields first, and proceed with
			// full unmarshaling only if the type is cilium-cni, to avoid possible
			// spurious warnings when trying to parse configs for other CNIs.
			if err := json.Unmarshal([]byte(nad.Spec.Config), &cfg.NADCNIConfigCore); err != nil {
				n.log.Warn("Failed to parse CNI configuration from NetworkAttachmentDefinition",
					logfields.Error, err,
					logfields.K8sNamespace, nad.GetNamespace(),
					logfields.Name, nad.GetName(),
				)
			}

			if cfg.Type == tables.NADCNIConfigTypeCilium {
				if err := json.Unmarshal([]byte(nad.Spec.Config), &cfg); err != nil {
					n.log.Warn("Failed to parse CNI configuration from NetworkAttachmentDefinition",
						logfields.Error, err,
						logfields.K8sNamespace, nad.GetNamespace(),
						logfields.Name, nad.GetName(),
					)
				}
			}

			return tables.NetworkAttachmentDefinition{
				NamespacedName: tables.NamespacedName{
					Namespace: nad.GetNamespace(),
					Name:      nad.GetName(),
				},

				Labels:          nad.GetLabels(),
				Annotations:     nad.GetAnnotations(),
				Managed:         nad.GetLabels()[managedByLabelKey] == managedByLabelVal,
				UID:             nad.GetUID(),
				ResourceVersion: nad.GetResourceVersion(),

				CNIConfig: cfg,
			}, true
		},
	})
}

func (n *NetworkAttachmentDefinitions) registerK8sReconciler(params reconciler.Params, cniLogsDebug CNILogsDebug) (
	reconciler.Reconciler[tables.DesiredNetworkAttachmentDefinition], error,
) {
	if !n.cfg.EnabledWithNADIntegration() {
		return nil, nil
	}

	return reconciler.Register(
		params,
		n.tbl,
		(tables.DesiredNetworkAttachmentDefinition).Clone,
		(tables.DesiredNetworkAttachmentDefinition).SetStatus,
		(tables.DesiredNetworkAttachmentDefinition).GetStatus,
		n.newReconcilerOps(cniLogsDebug),
		nil,
	)
}

func (n *NetworkAttachmentDefinitions) registerDesiredReconciler() {
	if !n.cfg.EnabledWithNADIntegration() {
		return
	}

	wtx := n.db.WriteTxn(n.tbl)
	initialized := n.tbl.RegisterInitializer(wtx, "desired-nads-initialized")
	wtx.Commit()

	n.jg.Add(job.OneShot("populate-desired-nads-table", func(ctx context.Context, health cell.Health) error {
		var initDone bool

		// Explicitly wait for NADs table initialization before starting the reconciliation.
		// This ensures that we already gathered a full snapshot of the existing NAD instances.
		health.OK("Waiting for NADs table initialization")
		_, wait := n.nads.Initialized(n.db.ReadTxn())
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}

		health.OK("Primed")
		wtx := n.db.WriteTxn(n.networks, n.namespaces, n.nads)
		netsChangeIter, _ := n.networks.Changes(wtx)
		nsesChangeIter, _ := n.namespaces.Changes(wtx)
		nadsChangeIter, _ := n.nads.Changes(wtx)
		wtx.Commit()

		for {
			var watchset = statedb.NewWatchSet()

			wtx := n.db.WriteTxn(n.tbl)
			netsChanges, netsWatch := netsChangeIter.Next(wtx)
			nsesChanges, nsesWatch := nsesChangeIter.Next(wtx)
			nadsChanges, nadsWatch := nadsChangeIter.Next(wtx)
			watchset.Add(netsWatch, nsesWatch, nadsWatch)

			for change := range netsChanges {
				if change.Deleted {
					n.deleteDesiredNADsForNetwork(wtx, change.Object.Name)
				} else {
					n.upsertDesiredNADsForNetwork(wtx, change.Object)
				}
			}

			for change := range nsesChanges {
				if change.Deleted {
					n.deleteDesiredNADsForNamespace(wtx, change.Object.Name)
				} else {
					n.upsertDesiredNADsForNamespace(wtx, change.Object)
				}
			}

			for change := range nadsChanges {
				// Whenever we observe a NAD change, we mark the corresponding
				// desired NAD, if any, as pending, so that the reconciler can
				// check whether an update is necessary to enforce the desired
				// state. We don't explicitly trigger the deletion of a managed
				// NAD if the corresponding desired NAD doesn't exist, as that's
				// taken care of by the periodic pruning process.
				n.markDesiredNADPending(wtx, change.Object.NamespacedName)
			}

			if !initDone {
				netsInit, new := n.networks.Initialized(wtx)
				nsesInit, nsw := n.namespaces.Initialized(wtx)

				switch {
				case !netsInit:
					watchset.Add(new)
				case !nsesInit:
					watchset.Add(nsw)
				default:
					initDone = true
					initialized(wtx)
				}
			}

			wtx.Commit()
			health.OK("Reconciliation completed")

			_, err := watchset.Wait(ctx, reconcilers.SettleTime)
			if err != nil {
				return err
			}
		}
	}))
}

func (n *NetworkAttachmentDefinitions) upsertDesiredNADsForNetwork(wtx statedb.WriteTxn, network tables.PrivateNetwork) {
	// Delete any stale entries that haven't been refreshed by the logic below.
	defer func(watermark statedb.Revision) {
		for nad, revision := range n.tbl.Prefix(wtx, tables.DesiredNADsByNetwork(network.Name)) {
			if revision <= watermark {
				n.tbl.Delete(wtx, nad)
			}
		}
	}(n.tbl.Revision(wtx))

	for namespace := range n.namespaces.All(wtx) {
		if !network.NADs.NamespaceSelector.Matches(labels.Set(namespace.Labels)) {
			continue
		}

		n.upsertDesiredNADsForNetworkAndNamespace(wtx, network, namespace.Name)
	}
}

func (n *NetworkAttachmentDefinitions) deleteDesiredNADsForNetwork(wtx statedb.WriteTxn, network tables.NetworkName) {
	for nad := range n.tbl.Prefix(wtx, tables.DesiredNADsByNetwork(network)) {
		n.tbl.Delete(wtx, nad)
	}
}

func (n *NetworkAttachmentDefinitions) upsertDesiredNADsForNamespace(wtx statedb.WriteTxn, namespace daemonk8s.Namespace) {
	// Delete any stale entries that haven't been refreshed by the logic below.
	defer func(watermark statedb.Revision) {
		for nad, revision := range n.tbl.Prefix(wtx, tables.DesiredNADsByNamespace(namespace.Name)) {
			if revision <= watermark {
				n.tbl.Delete(wtx, nad)
			}
		}
	}(n.tbl.Revision(wtx))

	for network := range n.networks.All(wtx) {
		if !network.NADs.NamespaceSelector.Matches(labels.Set(namespace.Labels)) {
			continue
		}

		n.upsertDesiredNADsForNetworkAndNamespace(wtx, network, namespace.Name)
	}
}

func (n *NetworkAttachmentDefinitions) deleteDesiredNADsForNamespace(wtx statedb.WriteTxn, namespace string) {
	for nad := range n.tbl.Prefix(wtx, tables.DesiredNADsByNamespace(namespace)) {
		n.tbl.Delete(wtx, nad)
	}
}

func (n *NetworkAttachmentDefinitions) markDesiredNADPending(wtx statedb.WriteTxn, nn tables.NamespacedName) {
	desired, _, found := n.tbl.Get(wtx, tables.DesiredNADByNamespacedName(nn))
	if !found {
		return
	}

	n.tbl.Insert(wtx, desired.SetStatus(reconciler.StatusPending()))
}

func (n *NetworkAttachmentDefinitions) upsertDesiredNADsForNetworkAndNamespace(
	wtx statedb.WriteTxn, network tables.PrivateNetwork, namespace string,
) {
	for _, subnet := range network.Subnets {
		nad, _, found := n.tbl.Get(wtx,
			tables.DesiredNADByNetworkSubnetAndNamespace(network.Name, subnet.Name, namespace),
		)

		if !found {
			name, err := n.desiredNADName(wtx, network.Name, subnet.Name, namespace)
			if err != nil {
				n.log.Warn("Failed to generate unique name for NetworkAttachmentDefinition",
					logfields.Error, err,
					logfields.ClusterwidePrivateNetwork, network.Name,
					logfields.PrivateNetworkSubnet, subnet.Name,
					logfields.K8sNamespace, namespace,
				)
				continue
			}

			nad = tables.DesiredNetworkAttachmentDefinition{
				NamespacedName: tables.NamespacedName{
					Namespace: namespace,
					Name:      name,
				},

				Network: network.Name,
				Subnet:  subnet.Name,
				Status:  reconciler.StatusPending(),
			}
		}

		n.tbl.Insert(wtx, nad)
	}
}

var base32Encoder = base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString

func (n *NetworkAttachmentDefinitions) desiredNADName(
	txn statedb.ReadTxn, network tables.NetworkName, subnet tables.SubnetName, namespace string,
) (string, error) {
	// Check if there already exists a managed NAD instance, in which case we inherit it.
	for nad := range n.nads.List(txn, tables.NADsByNetworkSubnetAndNamespace(network, subnet, namespace)) {
		if nad.Managed {
			return nad.Name, nil
		}
	}

	// Given the following constraints:
	//
	// * Network names conform to the RFC 1123 DNS Subdomain Names format (i.e., max 253 characters);
	// * Subnet names conform to the RFC 1123 Label Names format (i.e., max 63 characters);
	// * NAD names conform to the RFC 1123 DNS Subdomain Names format (i.e., max 253 characters);
	//   additionally, the Openshift webhook enforces the '^[a-z-1-9]([-a-z0-9]*[a-z0-9])?$' regex,
	//   preventing names starting with 0, and any dot.
	//
	// the NAD name is constructed as the concatenation of the network and subnet name, with the
	// network name being potentially shortened if it exceeds 180 characters (this leaves 10
	// characters of room for separators and hashes to guarantee uniqueness).
	network = tables.NetworkName(strings.ReplaceAll(string(network), ".", "-"))
	if strings.HasPrefix(string(network), "0") {
		network = "nad-" + network
	}

	const maxNetworkNameLen = 180
	if len(network) > maxNetworkNameLen {
		var hash = sha256.Sum256([]byte(network))
		network = tables.NetworkName(fmt.Sprintf("%s-%s", network[:maxNetworkNameLen], base32Encoder(hash[:])[:4]))
	}

	var (
		base = strings.ToLower(fmt.Sprintf("%s-%s", network, subnet))
		nn   = tables.NamespacedName{Namespace: namespace, Name: base}
	)

	// Make sure that the name isn't colliding with a different managed NAD. This can happen due to
	// problematic network and subnet name combinations (e.g., (foo, bar-baz) and (foo-bar, baz)),
	// given that the separator must be a valid character. In that case, we append an extra suffix
	// at the end to ensure uniqueness. Still, we don't do that by default, to ensure that names
	// are easily predictable in the common case. Additionally, we don't try to be resilient to
	// conflicts with user-managed NADs, to not make the logic even more complex. If that happens,
	// we'll simply backoff during creation, and bubble up the error there.
	for attempt := range 5 {
		_, _, found := n.tbl.Get(txn, tables.DesiredNADByNamespacedName(nn))
		if !found {
			return nn.Name, nil
		}

		var hash = sha256.Sum256(fmt.Appendf(nil, "%s|%s|%d", network, subnet, attempt))
		nn.Name = base + "-" + strings.ToLower(base32Encoder(hash[:])[:3])
	}

	return "", fmt.Errorf("conflict, despite retries")
}

func (n *NetworkAttachmentDefinitions) newCRDSyncPromise() promise.Promise[synced.CRDSync] {
	resolve, promise := promise.New[synced.CRDSync]()

	n.jg.Add(
		job.OneShot("wait-for-nad-crd", func(ctx context.Context, health cell.Health) error {
			health.OK("Checking if NetworkAttachmentDefinition CRD exists")
			_, err := n.crdcl.Get(ctx, nadv1.Resource("network-attachment-definitions").String(),
				metav1.GetOptions{})

			// We don't explicitly validate the CRD conditions, as the CRD is managed externally.
			if err == nil {
				resolve.Resolve(synced.CRDSync{})
				return nil
			}

			return fmt.Errorf("checking NetworkAttachmentDefinition CRD existence: %w", err)
		}, job.WithRetry(-1, &job.ExponentialBackoff{Min: 1 * time.Second, Max: 30 * time.Second})),
	)

	return promise
}

type networkAttachmentDefinitionsOps struct {
	client func(string) nadclientv1.NetworkAttachmentDefinitionInterface
	nads   statedb.Table[tables.NetworkAttachmentDefinition]
	log    *slog.Logger

	tmpl   tables.NADCNIConfig
	spacer *strings.Replacer
}

func (n *NetworkAttachmentDefinitions) newReconcilerOps(cniLogsDebug CNILogsDebug) *networkAttachmentDefinitionsOps {
	return &networkAttachmentDefinitionsOps{
		client: n.nadcl,
		nads:   n.nads,
		log:    n.log,

		tmpl: tables.NADCNIConfig{
			NADCNIConfigCore: tables.NADCNIConfigCore{
				CNIVersion: "0.3.1",
				Type:       tables.NADCNIConfigTypeCilium,
			},
			EnableDebug: bool(cniLogsDebug),
			LogFile:     n.cfg.NADIntegration.CNILogFile,
			LogFormat:   n.cfg.NADIntegration.CNILogFormat,
		},
		spacer: strings.NewReplacer(",", ", ", ":", ": "),
	}
}

func (n *networkAttachmentDefinitionsOps) Update(
	ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, desired tables.DesiredNetworkAttachmentDefinition,
) error {
	cnicfg, cnicfgstr, err := n.cniConfig(desired.Network, desired.Subnet)
	if err != nil {
		return err
	}

	nad, _, found := n.nads.Get(txn, tables.NADByNamespacedName(desired.NamespacedName))

	// The NAD does not exist in Kubernetes yet, hence we need to create it.
	if !found {
		_, err := n.client(desired.Namespace).Create(ctx, &nadv1.NetworkAttachmentDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: desired.Namespace, Name: desired.Name,
				Labels: map[string]string{
					managedByLabelKey: managedByLabelVal,
				},
			},
			Spec: nadv1.NetworkAttachmentDefinitionSpec{Config: cnicfgstr},
		}, metav1.CreateOptions{FieldManager: fieldManager})
		return err
	}

	// The object already exists, but is not managed by us.
	if !nad.Managed {
		return errors.New("already exists, but is not managed by us")
	}

	// The object is already up-to-date, no need for further operations.
	if nad.CNIConfig == cnicfg {
		return nil
	}

	// The object already exists, and is managed by us, hence we can update it.
	_, err = n.client(desired.Namespace).Update(ctx, &nadv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: desired.Namespace, Name: desired.Name,
			UID: nad.UID, ResourceVersion: nad.ResourceVersion,
			Labels:      maps.Clone(nad.Labels),
			Annotations: maps.Clone(nad.Annotations),
		},
		Spec: nadv1.NetworkAttachmentDefinitionSpec{Config: cnicfgstr},
	}, metav1.UpdateOptions{FieldManager: fieldManager})
	return err
}

func (n *networkAttachmentDefinitionsOps) Delete(
	ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, desired tables.DesiredNetworkAttachmentDefinition,
) error {
	nad, _, found := n.nads.Get(txn, tables.NADByNamespacedName(desired.NamespacedName))

	// The object appears to not exist. This can happen if we haven't created it
	// yet (or the creation operation failed), but also if we haven't observed
	// the creation event yet through the informer. Hence, we directly query the
	// API Server to make sure that we don't leave a leftover behind by mistake.
	if !found {
		got, err := n.client(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		switch {
		case k8serrors.IsNotFound(err):
			return nil
		case err != nil:
			return fmt.Errorf("getting NAD: %w", err)
		default:
			nad = tables.NetworkAttachmentDefinition{
				NamespacedName:  desired.NamespacedName,
				Managed:         got.GetLabels()[managedByLabelKey] == managedByLabelVal,
				UID:             got.GetUID(),
				ResourceVersion: got.GetResourceVersion(),
			}
		}
	}

	// The object is not managed by us, nothing to do.
	if !nad.Managed {
		return nil
	}

	return ctrlclient.IgnoreNotFound(
		n.client(nad.Namespace).Delete(ctx, nad.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &nad.UID, ResourceVersion: &nad.ResourceVersion},
		}),
	)
}

func (n *networkAttachmentDefinitionsOps) Prune(
	ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[tables.DesiredNetworkAttachmentDefinition, statedb.Revision],
) error {
	var desired = sets.New(statedb.Collect(statedb.Map(objects,
		func(nad tables.DesiredNetworkAttachmentDefinition) tables.NamespacedName { return nad.NamespacedName },
	))...)

	var errs error
	for nad := range n.nads.All(txn) {
		if !nad.Managed {
			continue
		}

		if desired.Has(nad.NamespacedName) {
			continue
		}

		n.log.Info("Pruning orphaned network attachment definition",
			logfields.K8sNamespace, nad.Namespace,
			logfields.Name, nad.Name,
		)

		errs = errors.Join(errs, ctrlclient.IgnoreNotFound(
			n.client(nad.Namespace).Delete(ctx, nad.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &nad.UID, ResourceVersion: &nad.ResourceVersion},
			}),
		))
	}

	return errs
}

func (n *networkAttachmentDefinitionsOps) cniConfig(network tables.NetworkName, subnet tables.SubnetName) (tables.NADCNIConfig, string, error) {
	var cnicfg = n.tmpl
	cnicfg.PrivateNetworks.Network = string(network)
	cnicfg.PrivateNetworks.Subnet = string(subnet)

	cnicfgstr, err := json.Marshal(cnicfg)
	if err != nil {
		return tables.NADCNIConfig{}, "", fmt.Errorf("marshaling CNI config: %w", err)
	}

	// Add a space after all occurrences of ',' and ':', to allow the resulting
	// string to be split into multiple lines when the NAD config stanza is
	// marshaled into yaml. We don't use [json.MarshalIndent] because that
	// would add proper newlines as well, that would not be actually rendered,
	// making the resulting string uglier and less human readable.
	return cnicfg, n.spacer.Replace(string(cnicfgstr)), nil
}

func newNADsClient(cfg config.Config, client client.Clientset) (nadclientv1.K8sCniCncfIoV1Interface, error) {
	if !cfg.EnabledWithNADIntegration() {
		return nil, nil
	}

	if !client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	out, err := nadclient.NewForConfig(client.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to create network attachment definitions client: %w", err)
	}

	return out.K8sCniCncfIoV1(), nil
}
