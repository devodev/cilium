// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/pkg/comparator"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/policy/utils"
)

const (
	TierAdmin    = "Admin"
	TierNormal   = "Normal"
	TierBaseline = "Baseline"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:categories={cilium,ciliumpolicy,isovalent},singular="isovalentnetworkpolicy",path="isovalentnetworkpolicies",scope="Namespaced",shortName={inp,isovalentnp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Valid')].status",name="Valid",type=string
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// IsovalentNetworkPolicy is a Kubernetes third-party resource with an extended
// version of CiliumNetworkPolicy.
type IsovalentNetworkPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Isovalent specific rule specification.
	//+kubebuilder:validation:XValidation:message="Order must be >= 0.0",rule="!has(self.order) || self.order >= 0.0"
	//+kubebuilder:validation:XValidation:message="Tier must be Normal or Baseline",rule="!has(self.tier) || self.tier == 'Normal' || self.tier == 'Baseline'"
	Spec *IsovalentNetworkPolicyRule `json:"spec,omitempty"`

	// Specs is a list of desired Isovalent specific rule specification.
	//+kubebuilder:validation:items:XValidation:message="Order must be >= 0.0",rule="!has(self.order) || self.order >= 0.0"
	Specs []*IsovalentNetworkPolicyRule `json:"specs,omitempty"`
	// TODO(CDC) add CEL for Normal / Baseline tier. It triggers the complexity limits currently.

	// Status is the status of the Isovalent policy rule
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status IsovalentNetworkPolicyStatus `json:"status"`
}

// DeepEqual compares 2 INPs.
func (in *IsovalentNetworkPolicy) DeepEqual(other *IsovalentNetworkPolicy) bool {
	return objectMetaDeepEqual(in.ObjectMeta, other.ObjectMeta) && in.deepEqual(other)
}

// objectMetaDeepEqual performs an equality check for metav1.ObjectMeta that
// ignores the LastAppliedConfigAnnotation. This function's usage is shared
// among INP and ICNP as they have the same structure.
func objectMetaDeepEqual(in, other metav1.ObjectMeta) bool {
	if !(in.Name == other.Name && in.Namespace == other.Namespace) {
		return false
	}

	return comparator.MapStringEqualsIgnoreKeys(
		in.GetAnnotations(),
		other.GetAnnotations(),
		// Ignore v1.LastAppliedConfigAnnotation annotation
		[]string{v1.LastAppliedConfigAnnotation})
}

// IsovalentNetworkPolicyRule is a policy rule which must be applied to all endpoints which match
// the labels contained in the endpointSelector
//
// Each rule is split into an ingress section which contains all rules
// applicable at ingress, and an egress section applicable at egress. For rule
// types such as `L4Rule` and `CIDR` which can be applied at both ingress and
// egress, both ingress and egress side have to either specifically allow the
// connection or one side has to be omitted.
//
// Either ingress, egress, or both can be provided. If both ingress and egress
// are omitted, the rule has no effect.
//
// +deepequal-gen:private-method=true
type IsovalentNetworkPolicyRule struct {
	api.Rule `json:",inline"`

	// IngressPass is a list of ingress traffic to pass to lower tiers.
	//
	// Traffic that is passed will skip any lower-priority rules on the same
	// tier, even if they are deny. The traffic will not be explicitly allowed.
	// Rather, rules in lower tiers have the option to permit this traffic.
	IngressPass []api.IngressRule `json:"ingressPass,omitempty"`

	// EgressPass is a list of egress traffic to pass to lower tiers.
	//
	// Traffic that is passed will skip any lower-priority rules on the same
	// tier, even if they are deny. The traffic will not be explicitly allowed.
	// Rather, rules in lower tiers have the option to permit this traffic.
	EgressPass []api.EgressRule `json:"egressPass,omitempty"`

	// Order specifies the order in which the policy is applied. It applies
	// within a given Tier. The default is 0. Negative and fractional
	// values are permitted.
	Order *float32 `json:"order,omitempty"`

	// Tier indicates the tier at which this policy should apply.
	//
	// This can be a number between 1 and 254, or the strings
	// Admin, Normal, or Baseline. The default is Normal.
	//
	// - Admin is equal to tier 100
	// - Normal is equal to tier 200
	// - Baseline is equal to tier 250
	//
	//+deepequal-gen=false
	//+kubebuilder:validation:XIntOrString
	//+kubebuilder:validation:Pattern="^([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4]|Admin|Normal|Baseline)$"
	Tier *intstr.IntOrString `json:"tier,omitempty"`
}

func (r *IsovalentNetworkPolicyRule) DeepEqual(o *IsovalentNetworkPolicyRule) bool {
	switch {
	case (r == nil) != (o == nil):
		return false
	case (r == nil) && (o == nil):
		return true
	}

	// nil tolerant
	if r.Tier.String() != o.Tier.String() {
		return false
	}

	return r.deepEqual(o)
}

// +deepequal-gen=true

// IsovalentNetworkPolicyStatus is the status of an Isovalent policy rule.
type IsovalentNetworkPolicyStatus struct {
	// DerivativePolicies is the status of all policies derived from the Isovalent
	// policy
	DerivativePolicies map[string]IsovalentNetworkPolicyNodeStatus `json:"derivativePolicies,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []NetworkPolicyCondition `json:"conditions,omitempty"`
}

// +deepequal-gen=true

// IsovalentNetworkPolicyNodeStatus is the status of an Isovalent policy rule for a
// specific node.
type IsovalentNetworkPolicyNodeStatus struct {
	// OK is true when the policy has been parsed and imported successfully
	// into the in-memory policy repository on the node.
	OK bool `json:"ok,omitempty"`

	// Error describes any error that occurred when parsing or importing the
	// policy, or realizing the policy for the endpoints to which it applies
	// on the node.
	Error string `json:"error,omitempty"`

	// LastUpdated contains the last time this status was updated
	LastUpdated slimv1.Time `json:"lastUpdated,omitempty"`

	// Revision is the policy revision of the repository which first implemented
	// this policy.
	Revision uint64 `json:"localPolicyRevision,omitempty"`

	// Enforcing is set to true once all endpoints present at the time the
	// policy has been imported are enforcing this policy.
	Enforcing bool `json:"enforcing,omitempty"`

	// Annotations corresponds to the Annotations in the ObjectMeta of the INP
	// that have been realized on the node for INP. That is, if an INP has been
	// imported and has been assigned annotation X=Y by the user,
	// Annotations in IsovalentNetworkPolicyNodeStatus will be X=Y once the
	// INP that was imported corresponding to Annotation X=Y has been realized on
	// the node.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CreateINPNodeStatus returns an IsovalentNetworkPolicyNodeStatus created from the
// provided fields.
func CreateINPNodeStatus(enforcing, ok bool, inpError error, rev uint64, annotations map[string]string) IsovalentNetworkPolicyNodeStatus {
	inpns := IsovalentNetworkPolicyNodeStatus{
		Enforcing:   enforcing,
		Revision:    rev,
		OK:          ok,
		LastUpdated: slimv1.Now(),
		Annotations: annotations,
	}
	if inpError != nil {
		inpns.Error = inpError.Error()
	}
	return inpns
}

func (r *IsovalentNetworkPolicy) String() string {
	result := ""
	result += fmt.Sprintf("TypeMeta: %s, ", r.TypeMeta.String())
	result += fmt.Sprintf("ObjectMeta: %s, ", r.ObjectMeta.String())
	if r.Spec != nil {
		result += fmt.Sprintf("Spec: %v", *(r.Spec))
	}
	if r.Specs != nil {
		result += fmt.Sprintf("Specs: %v", r.Specs)
	}
	result += fmt.Sprintf("Status: %v", r.Status)
	return result
}

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *IsovalentNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status IsovalentNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]IsovalentNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
}

func (r *IsovalentNetworkPolicy) rules() iter.Seq[*IsovalentNetworkPolicyRule] {
	return func(yield func(*IsovalentNetworkPolicyRule) bool) {
		if r.Spec != nil {
			if !yield(r.Spec) {
				return
			}
		}

		for _, rule := range r.Specs {
			if rule != nil {
				if !yield(rule) {
					return
				}
			}
		}
	}
}

func (r *IsovalentNetworkPolicy) Sanitize() error {
	var errs error
	if r.ObjectMeta.Name == "" {
		errs = errors.Join(errs, NewErrParse("IsovalentNetworkPolicy must have name"))
	}
	if r.ObjectMeta.Namespace == "" {
		errs = errors.Join(errs, NewErrParse("IsovalentNetworkPolicy must have namespace"))
	}
	if r.Spec == nil && r.Specs == nil {
		errs = errors.Join(errs, ErrEmptyINP)
	}
	for rule := range r.rules() {
		errs = errors.Join(errs, rule.Sanitize(false))
	}
	return errs
}

// Parse parses an IsovalentNetworkPolicy and returns a list of cilium policy
// rules.
func (r *IsovalentNetworkPolicy) Parse(logger *slog.Logger, clusterName string) (policytypes.PolicyEntries, error) {
	// Temporary fix for ICNPs. See #12834 (which refers to CCNPs).
	// TL;DR. ICNPs are converted into SlimINPs and end up here so we need to
	// convert them back to ICNPs to allow proper parsing.
	if r.Namespace == "" {
		icnp := IsovalentClusterwideNetworkPolicy{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: r.ObjectMeta,
			Spec:       r.Spec,
			Specs:      r.Specs,
			Status:     r.Status,
		}
		return icnp.Parse(logger, clusterName)
	}

	if err := r.Sanitize(); err != nil {
		return nil, err
	}

	out := make(policytypes.PolicyEntries, 0, len(r.Specs)+1)

	for rule := range r.rules() {
		entries := rule.parseToPolicyEntries(logger, clusterName, r.ObjectMeta)
		out = append(out, entries...)
	}

	return out, nil
}

func (r *IsovalentNetworkPolicyRule) Sanitize(isICNP bool) error {
	// valid rules with just ingressPass / egressPass fail upstream validation,
	// as they have no stanzas. We must make a fake rule.
	fakeAllowDeny, fakePass := r.splitPassRule()
	if fakeAllowDeny != nil {
		if err := fakeAllowDeny.Rule.Sanitize(); err != nil {
			return err
		}
	}
	if fakePass != nil {
		if err := fakePass.Rule.Sanitize(); err != nil {
			return err
		}
	}

	if _, err := r.parseTier(); err != nil {
		return err
	}

	if !isICNP {
		if err := r.sanitizeINP(); err != nil {
			return err
		}
	}

	for _, ingress := range r.Ingress {
		if len(ingress.FromGroups) != 0 {
			return errors.New("ingress.fromGroups is not supported in IsovalentNetworkPolicy")
		}
	}
	for _, ingress := range r.IngressDeny {
		if len(ingress.FromGroups) != 0 {
			return errors.New("ingressDeny.fromGroups is not supported in IsovalentNetworkPolicy")
		}
	}
	for _, ingress := range r.IngressPass {
		if len(ingress.FromGroups) != 0 {
			return errors.New("ingressPass.fromGroups is not supported in IsovalentNetworkPolicy")
		}
	}
	for _, egress := range r.Egress {
		if len(egress.ToGroups) != 0 {
			return errors.New("egress.toGroups is not supported in IsovalentNetworkPolicy")
		}
	}
	for _, egress := range r.EgressDeny {
		if len(egress.ToGroups) != 0 {
			return errors.New("egressDeny.toGroups is not supported in IsovalentNetworkPolicy")
		}
	}
	for _, egress := range r.EgressPass {
		if len(egress.ToGroups) != 0 {
			return errors.New("egressPass.toGroups is not supported in IsovalentNetworkPolicy")
		}
	}
	return nil
}

// sanitizeINP applies INP-only restrictions that do not apply to an ICNP.
func (r *IsovalentNetworkPolicyRule) sanitizeINP() error {
	if r.NodeSelector.LabelSelector != nil {
		return NewErrParse("Invalid IsovalentNetworkPolicy spec: rule cannot have NodeSelector")
	}

	if order := r.Order; order != nil && *order < 0 {
		return errors.New("IsovalentNetworkPolicy rule order must be ≥ 0")
	}
	if r.Tier != nil {
		if r.Tier.Type != intstr.String {
			return errors.New("IsovalentNetworkPolicy Tier must be the names Normal or Baseline")
		}
		switch r.Tier.StrVal {
		case TierNormal, TierBaseline, "":
		default:
			return errors.New("IsovalentNetworkPolicy Tier must be the names Normal or Baseline")
		}
	}
	return nil
}

// splitPassRule makes two rules: one with existing allow and deny statements. The other
// is with any pass statements moved to allow, and without allow and deny.
// One or the other may be nil.
// This is necessary because we are tricking the OSS code in to parsing INP rules for us, but it doesn't
// understand Pass rules. So, we convert them to allow rules instead.
func (r *IsovalentNetworkPolicyRule) splitPassRule() (allowDenyRule, fakePassRule *IsovalentNetworkPolicyRule) {
	if len(r.IngressPass)+len(r.EgressPass) == 0 {
		return r, nil
	}

	// make copy of rule with pass moved to allow
	fakePassRule = r.DeepCopy()
	fakePassRule.EgressDeny = nil
	fakePassRule.IngressDeny = nil
	fakePassRule.Ingress = r.IngressPass
	fakePassRule.Egress = r.EgressPass
	fakePassRule.IngressPass = nil
	fakePassRule.EgressPass = nil

	// only pass rules, don't set allowDenyRule
	if len(r.Ingress)+len(r.Egress)+len(r.IngressDeny)+len(r.EgressDeny) == 0 {
		return
	}

	allowDenyRule = r.DeepCopy()
	allowDenyRule.IngressPass = nil
	allowDenyRule.EgressPass = nil

	return
}

func (r *IsovalentNetworkPolicyRule) parseToPolicyEntries(logger *slog.Logger, clusterName string, objectMeta metav1.ObjectMeta) policytypes.PolicyEntries {
	var out policytypes.PolicyEntries

	// The OSS code doesn't understand pass verdicts. What's more, it *rejects* rules
	// that don't have an allow or deny stanza.
	//
	// So, we make a fake allow rule with the pass verdicts
	allowDenyRule, fakePassRule := r.splitPassRule()

	makeEntries := func(rule *IsovalentNetworkPolicyRule, isFakePass bool) {
		if rule == nil {
			return
		}

		// Sanitize is side-effecting, we must re-run it.
		// In addition to validation, it also fills in defaults and pre-parses
		// selectors. ParseToCiliumRule relies on these being set.
		//
		// In this code path, it will never fail (since we sanitized before).
		if err := rule.Rule.Sanitize(); err != nil {
			logger.Error("BUG: failed to sanitize pseudo pass-allow rule",
				logfields.Error, err)
			return
		}

		cr := k8sCiliumUtils.ParseToCiliumRule(logger, clusterName, objectMeta.Namespace, objectMeta.Name, objectMeta.UID, &rule.Rule)
		ruleEntries := utils.RulesToPolicyEntries(api.Rules{cr})
		for _, re := range ruleEntries {
			if rule.Order != nil {
				re.Priority = float64(*rule.Order)
			}

			if isFakePass {
				if re.Verdict != policytypes.Allow {
					logger.Warn("BUG: pass conversion resulted in non-allow verdict?")
				} else {
					re.Verdict = policytypes.Pass
				}
			}

			// already sanitized above
			re.Tier, _ = rule.parseTier()
			out = append(out, re)
		}
	}

	makeEntries(allowDenyRule, false)
	makeEntries(fakePassRule, true)

	return out
}

// parseTier parses the string or int Tier to the corresponding numeric value.
// returns tier 255 (the lowest tier) on error, to prevent a logic error elevating
// a rule to the highest tier
func (r *IsovalentNetworkPolicyRule) parseTier() (policytypes.Tier, error) {
	if r.Tier == nil {
		return policytypes.Normal, nil
	}

	if r.Tier.Type == intstr.String {
		switch r.Tier.StrVal {
		case TierAdmin:
			return policytypes.Admin, nil
		case TierNormal, "":
			return policytypes.Normal, nil
		case TierBaseline:
			return policytypes.Baseline, nil
		default:
			return 255, fmt.Errorf("Invalid Rule tier name %s, must be Admin, Normal, or Baseline", r.Tier.StrVal)
		}
	}

	if r.Tier.IntVal < 1 || r.Tier.IntVal >= 255 {
		return 255, fmt.Errorf("Invalid Rule tier value %d, must be between 1 and 254", r.Tier.IntVal)
	}
	return policytypes.Tier(r.Tier.IntVal), nil
}

// GetIdentityLabels returns all rule labels in the IsovalentNetworkPolicy.
func (r *IsovalentNetworkPolicy) GetIdentityLabels() labels.LabelArray {
	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	// Even though the struct represents IsovalentNetworkPolicy, we use it both for
	// IsovalentNetworkPolicy and IsovalentClusterwideNetworkPolicy, so here we check for namespace
	// to send correct derivedFrom label to get the correct policy labels.
	derivedFrom := IsovalentNetworkPolicyKindDefinition
	if namespace == "" {
		derivedFrom = IsovalentClusterwideNetworkPolicyKindDefinition
	}
	return k8sCiliumUtils.GetPolicyLabels(namespace, name, uid, derivedFrom)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentNetworkPolicyList is a list of IsovalentNetworkPolicy objects.
type IsovalentNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentNetworkPolicy
	Items []IsovalentNetworkPolicy `json:"items"`
}

type PolicyConditionType string

const (
	PolicyConditionValid PolicyConditionType = "Valid"
)

type NetworkPolicyCondition struct {
	// The type of the policy condition
	Type PolicyConditionType `json:"type"`
	// The status of the condition, one of True, False, or Unknown
	Status v1.ConditionStatus `json:"status"`
	// The last time the condition transitioned from one status to another.
	// +optional
	LastTransitionTime slimv1.Time `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// A human readable message indicating details about the transition.
	// +optional
	Message string `json:"message,omitempty"`
}
