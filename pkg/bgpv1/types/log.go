// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

const (
	// ReconcilerLogField is used as key for reconciler name in the log field.
	ReconcilerLogField = "reconciler"

	// BGPNodeConfigLogField is used as key for BGP node config resource
	BGPNodeConfigLogField = "bgp_node_config"

	// InstanceLogField is used as key for BGP instance.
	InstanceLogField = "instance"

	// LocalASNLogField is used as key for BGP instance AS number
	LocalASNLogField = "asn"

	// ListenPortLogField is used as key for local port of BGP instance
	ListenPortLogField = "listen_port"

	// RouterIDLogField is used as key for BGP instance router ID
	RouterIDLogField = "router_id"

	// PeerLogField is used as key for BGP peer in the log field.
	PeerLogField = "peer"

	// FamilyLogField is used as key for BGP peer address family in the log field.
	FamilyLogField = "family"

	// PathLogField is used as key for BGP path in the log field.
	PathLogField = "path"

	// PrefixLogField is used as key for BGP prefix in the log field.
	PrefixLogField = "prefix"

	// AdvertTypeLogField is used as key for BGP advertisement type in the log field.
	AdvertTypeLogField = "advertisement_type"

	// PodIPPoolLogField is used as key for Pod IP pool in the log field.
	PodIPPoolLogField = "pod_ip_pool"

	// PolicyLogField is used as key for BGP policy in the log field.
	PolicyLogField = "policy"

	// ResourceLogField is used as key for k8s resource in the log field.
	ResourceLogField = "resource"

	// ComponentLogField ...
	ComponentLogField = "component"

	// NodeLabelsLogField ...
	NodeLabelsLogField = "nodeLabels"

	// PolicyNodeSelectorLogField ...
	PolicyNodeSelectorLogField = "policyNodeSelector"

	// SubsysLogField ...
	SubsysLogField = "subsys"

	// NameLogField ...
	NameLogField = "name"

	// NLRILogField ...
	NLRILogField = "NLRI"

	// PeerASNLogField ...
	PeerASNLogField = "peer_asn"

	// SecretRefLogField ...
	SecretRefLogField = "secret_ref"

	// FromPortLogField ...
	FromPortLogField = "from_port"

	// ToPortLogField ...
	ToPortLogField = "to_port"

	// FromRouterIDLogField ...
	FromRouterIDLogField = "from_router_id"

	// ToRouterIDLogField ...
	ToRouterIDLogField = "to_router_id"

	// PriorityLogField ...
	PriorityLogField = "priority"

	// ExistingPriorityLogField ...
	ExistingPriorityLogField = "existing_priority"

	// PeerEventLogField ...
	PeerEventLogField = "peer_event"

	// RouteLogField ...
	RouteLogField = "route_event"

	// PodCIDRAnnouncementsLogField ...
	PodCIDRAnnouncementsLogField = "pod_cidr_announcements"

	// PodCIDRUpdatedLogField ...
	PodCIDRUpdatedLogField = "pod_cidr_updated"

	// PodIPPoolLogFieldUpdatedLogField ...
	PodIPPoolLogFieldUpdatedLogField = "pod_ip_pool_updated"

	// ServicesAnnouncementsLogField ...
	ServicesAnnouncementsLogField = "services_announcements"

	// ServicesUpdatedLogField ...
	ServicesUpdatedLogField = "services_updated"

	// DiffLogField ...
	DiffLogField = "diff"

	// UpdatedInstancesLogField ...
	UpdatedInstancesLogField = "updated_instances"

	// DirectionLogField is a log field for direction of BGP reset
	DirectionLogField = "direction"
)
