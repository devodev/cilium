// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/container/cache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// PathDelimiter is the delimiter used in the labels paths.
	PathDelimiter = "."

	// IDNameHost is the label used for the hostname ID.
	IDNameHost = "host"

	// IDNameRemoteNode is the label used to describe the
	// ReservedIdentityRemoteNode
	IDNameRemoteNode = "remote-node"

	// IDNameWorld is the label used for the world ID.
	IDNameWorld = "world"

	// IDNameWorldIPv4 is the label used for the world-ipv4 ID, to distinguish
	// it from world-ipv6 in dual-stack mode.
	IDNameWorldIPv4 = "world-ipv4"

	// IDNameWorldIPv6 is the label used for the world-ipv6 ID, to distinguish
	// it from world-ipv4 in dual-stack mode.
	IDNameWorldIPv6 = "world-ipv6"

	// IDNameCluster is the label used to identify an unspecified endpoint
	// inside the cluster
	IDNameCluster = "cluster"

	// IDNameHealth is the label used for the local cilium-health endpoint
	IDNameHealth = "health"

	// IDNameInit is the label used to identify any endpoint that has not
	// received any labels yet.
	IDNameInit = "init"

	// IDNameKubeAPIServer is the label used to identify the kube-apiserver. It
	// is part of the reserved identity 7 and it is also used in conjunction
	// with IDNameHost if the kube-apiserver is running on the local host.
	IDNameKubeAPIServer = "kube-apiserver"

	// IDNameEncryptedOverlay is the label used to identify encrypted overlay
	// traffic.
	//
	// It is part of the reserved identity 11 and signals that overlay traffic
	// with this identity must be IPSec encrypted before leaving the host.
	//
	// This identity should never be seen on the wire and is used only on the
	// local host.
	IDNameEncryptedOverlay = "overlay-to-encrypt"

	// IDNameIngress is the label used to identify Ingress proxies. It is part
	// of the reserved identity 8.
	IDNameIngress = "ingress"

	// IDNameNone is the label used to identify no endpoint or other L3 entity.
	// It will never be assigned and this "label" is here for consistency with
	// other Entities.
	IDNameNone = "none"

	// IDNameUnmanaged is the label used to identify unmanaged endpoints
	IDNameUnmanaged = "unmanaged"

	// IDNameUnknown is the label used to to identify an endpoint with an
	// unknown identity.
	IDNameUnknown = "unknown"
)

var (
	// LabelHealth is the label used for health.
	LabelHealth = Labels{IDNameHealth: NewLabel(IDNameHealth, "", LabelSourceReserved)}

	// LabelHost is the label used for the host endpoint.
	LabelHost = Labels{IDNameHost: NewLabel(IDNameHost, "", LabelSourceReserved)}

	// LabelWorld is the label used for world.
	LabelWorld = Labels{IDNameWorld: NewLabel(IDNameWorld, "", LabelSourceReserved)}

	// LabelWorldIPv4 is the label used for world-ipv4.
	LabelWorldIPv4 = Labels{IDNameWorldIPv4: NewLabel(IDNameWorldIPv4, "", LabelSourceReserved)}

	// LabelWorldIPv6 is the label used for world-ipv6.
	LabelWorldIPv6 = Labels{IDNameWorldIPv6: NewLabel(IDNameWorldIPv6, "", LabelSourceReserved)}

	// LabelRemoteNode is the label used for remote nodes.
	LabelRemoteNode = Labels{IDNameRemoteNode: NewLabel(IDNameRemoteNode, "", LabelSourceReserved)}

	// LabelKubeAPIServer is the label used for the kube-apiserver. See comment
	// on IDNameKubeAPIServer.
	LabelKubeAPIServer = Labels{IDNameKubeAPIServer: NewLabel(IDNameKubeAPIServer, "", LabelSourceReserved)}

	LabelKubeAPIServerExt = Labels{
		IDNameKubeAPIServer: NewLabel(IDNameKubeAPIServer, "", LabelSourceReserved),
		IDNameWorld:         NewLabel(IDNameWorld, "", LabelSourceReserved),
	}

	// LabelIngress is the label used for Ingress proxies. See comment
	// on IDNameIngress.
	LabelIngress = Labels{IDNameIngress: NewLabel(IDNameIngress, "", LabelSourceReserved)}

	// LabelKeyFixedIdentity is the label that can be used to define a fixed
	// identity.
	LabelKeyFixedIdentity = "io.cilium.fixed-identity"
)

const (
	// LabelSourceUnspec is a label with unspecified source
	LabelSourceUnspec = "unspec"

	// LabelSourceAny is a label that matches any source
	LabelSourceAny = "any"

	// LabelSourceAnyKeyPrefix is prefix of a "any" label
	LabelSourceAnyKeyPrefix = LabelSourceAny + "."

	// LabelSourceK8s is a label imported from Kubernetes
	LabelSourceK8s = "k8s"

	// LabelSourceK8sKeyPrefix is prefix of a Kubernetes label
	LabelSourceK8sKeyPrefix = LabelSourceK8s + "."

	// LabelSourceContainer is a label imported from the container runtime
	LabelSourceContainer = "container"

	// LabelSourceCNI is a label imported from the CNI plugin
	LabelSourceCNI = "cni"

	// LabelSourceReserved is the label source for reserved types.
	LabelSourceReserved = "reserved"

	// LabelSourceCIDR is the label source for generated CIDRs.
	LabelSourceCIDR = "cidr"

	// LabelSourceCIDRGroup is the label source used for labels from CIDRGroups
	LabelSourceCIDRGroup = "cidrgroup"

	// LabelSourceCIDRGroupKeyPrefix is the source as a k8s selector key prefix
	LabelSourceCIDRGroupKeyPrefix = LabelSourceCIDRGroup + "."

	// LabelSourceNode is the label source for remote-nodes.
	LabelSourceNode = "node"

	// LabelSourceFQDN is the label source for IPs resolved by fqdn lookups
	LabelSourceFQDN = "fqdn"

	// LabelSourceReservedKeyPrefix is the prefix of a reserved label
	LabelSourceReservedKeyPrefix = LabelSourceReserved + "."

	// LabelSourceDirectory is the label source for policies read from files
	LabelSourceDirectory = "directory"
)

// Label is the Cilium's representation of a container label.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	// Source can be one of the above values (e.g.: LabelSourceContainer).
	//
	// +kubebuilder:validation:Optional
	Source string `json:"source"`

	// optimization for CIDR prefixes
	// +deepequal-gen=false
	cidr *netip.Prefix `json:"-"`
}

// Labels is a map of labels where the map's key is the same as the label's key.
type Labels map[string]Label

//
// Convenience functions to use instead of Has(), which iterates through the labels
//

// HasLabelWithKey returns true if lbls has a label with 'key'
func (l Labels) HasLabelWithKey(key string) bool {
	_, ok := l[key]
	return ok
}

func (l Labels) HasFixedIdentityLabel() bool {
	return l.HasLabelWithKey(LabelKeyFixedIdentity)
}

func (l Labels) HasInitLabel() bool {
	return l.HasLabelWithKey(IDNameInit)
}

func (l Labels) HasHealthLabel() bool {
	return l.HasLabelWithKey(IDNameHealth)
}

func (l Labels) HasIngressLabel() bool {
	return l.HasLabelWithKey(IDNameIngress)
}

func (l Labels) HasHostLabel() bool {
	return l.HasLabelWithKey(IDNameHost)
}

func (l Labels) HasKubeAPIServerLabel() bool {
	return l.HasLabelWithKey(IDNameKubeAPIServer)
}

func (l Labels) HasRemoteNodeLabel() bool {
	return l.HasLabelWithKey(IDNameRemoteNode)
}

func (l Labels) HasWorldIPv6Label() bool {
	return l.HasLabelWithKey(IDNameWorldIPv6)
}

func (l Labels) HasWorldIPv4Label() bool {
	return l.HasLabelWithKey(IDNameWorldIPv4)
}

func (l Labels) HasNonDualstackWorldLabel() bool {
	return l.HasLabelWithKey(IDNameWorld)
}

func (l Labels) HasWorldLabel() bool {
	return l.HasNonDualstackWorldLabel() || l.HasWorldIPv4Label() || l.HasWorldIPv6Label()
}

// GetPrintableModel turns the Labels into a sorted list of strings
// representing the labels.
func (l Labels) GetPrintableModel() (res []string) {
	res = make([]string, 0, len(l))
	for _, v := range l {
		if v.Source == LabelSourceCIDR {
			prefix, err := LabelToPrefix(v.Key)
			if err != nil {
				res = append(res, v.String())
			} else {
				res = append(res, LabelSourceCIDR+":"+prefix.String())
			}
		} else {
			// not a CIDR label, no magic needed
			res = append(res, v.String())
		}
	}

	slices.Sort(res)
	return res
}

// String returns the map of labels as human readable string
func (l Labels) String() string {
	return strings.Join(l.GetPrintableModel(), ",")
}

// Equals returns true if the two Labels contain the same set of labels.
func (l Labels) Equals(other Labels) bool {
	if len(l) != len(other) {
		return false
	}

	for k, lbl1 := range l {
		if lbl2, ok := other[k]; ok {
			if lbl1.Source == lbl2.Source && lbl1.Key == lbl2.Key && lbl1.Value == lbl2.Value {
				continue
			}
		}
		return false
	}
	return true
}

// GetFromSource returns all labels that are from the given source.
func (l Labels) GetFromSource(source string) Labels {
	lbls := Labels{}
	for k, v := range l {
		if v.Source == source {
			lbls[k] = v
		}
	}
	return lbls
}

// RemoveFromSource removes all labels that are from the given source
func (l Labels) RemoveFromSource(source string) {
	maps.DeleteFunc(l, func(k string, v Label) bool {
		return v.Source == source
	})
}

// NewLabel returns a new label from the given key, value and source. If source is empty,
// the default value will be LabelSourceUnspec. If key starts with '$', the source
// will be overwritten with LabelSourceReserved. If key contains ':', the value
// before ':' will be used as source if given source is empty, otherwise the value before
// ':' will be deleted and unused.
func NewLabel(key string, value string, source string) Label {
	var src string
	src, key = parseSource(key, ':')
	if source == "" {
		if src == "" {
			source = LabelSourceUnspec
		} else {
			source = src
		}
	}
	if src == LabelSourceReserved && key == "" {
		key = value
		value = ""
	}

	l := Label{
		Key:    cache.Strings.Get(key),
		Value:  cache.Strings.Get(value),
		Source: cache.Strings.Get(source),
	}
	if l.Source == LabelSourceCIDR {
		c, err := LabelToPrefix(l.Key)
		if err != nil {
			// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
			logging.DefaultSlogLogger.Error("Failed to parse CIDR label: invalid prefix.",
				logfields.Error, err,
				logfields.Key, l.Key,
			)
		} else {
			l.cidr = &c
		}
	}

	return l
}

// Equals returns true if source, Key and Value are equal and false otherwise.
func (l *Label) Equals(b *Label) bool {
	if !l.IsAnySource() && l.Source != b.Source {
		return false
	}
	return l.Key == b.Key && l.Value == b.Value
}

// IsAnySource return if the label was set with source "any".
func (l *Label) IsAnySource() bool {
	return l.Source == LabelSourceAny
}

// IsReservedSource return if the label was set with source "Reserved".
func (l *Label) IsReservedSource() bool {
	return l.Source == LabelSourceReserved
}

// Has returns true label L contains target.
// target may be "looser" w.r.t source or cidr, i.e.
// "k8s:foo=bar".Has("any:foo=bar") is true
// "any:foo=bar".Has("k8s:foo=bar") is false
// "cidr:10.0.0.1/32".Has("cidr:10.0.0.0/24") is true
func (l *Label) Has(target *Label) bool {
	return l.HasKey(target) && l.Value == target.Value
}

// HasKey returns true if l has target's key.
// target may be "looser" w.r.t source or cidr, i.e.
// "k8s:foo=bar".HasKey("any:foo") is true
// "any:foo=bar".HasKey("k8s:foo") is false
// "cidr:10.0.0.1/32".HasKey("cidr:10.0.0.0/24") is true
// "cidr:10.0.0.0/24".HasKey("cidr:10.0.0.1/32") is false
func (l *Label) HasKey(target *Label) bool {
	if !target.IsAnySource() && l.Source != target.Source {
		return false
	}

	// Do cidr-aware matching if both sources are "cidr".
	if target.Source == LabelSourceCIDR && l.Source == LabelSourceCIDR {
		tc := target.cidr
		if tc == nil {
			v, err := LabelToPrefix(target.Key)
			if err != nil {
				tc = &v
			}
		}
		lc := l.cidr
		if lc == nil {
			v, err := LabelToPrefix(l.Key)
			if err != nil {
				lc = &v
			}
		}
		if tc != nil && lc != nil && tc.Bits() <= lc.Bits() && tc.Contains(lc.Addr()) {
			return true
		}
	}

	return l.Key == target.Key
}

// String returns the string representation of Label in the for of Source:Key=Value or
// Source:Key if Value is empty.
func (l *Label) String() string {
	if len(l.Value) != 0 {
		return l.Source + ":" + l.Key + "=" + l.Value
	}
	return l.Source + ":" + l.Key
}

func (l *Label) BuildString(sb *strings.Builder) {
	sb.WriteString(l.Source)
	sb.WriteString(":")
	sb.WriteString(l.Key)
	if len(l.Value) != 0 {
		sb.WriteString("=")
		sb.WriteString(l.Value)
	}
}

func (l *Label) BuildBytes(buf *bytes.Buffer) {
	buf.WriteString(l.Source)
	buf.WriteString(":")
	buf.WriteString(l.Key)
	if len(l.Value) != 0 {
		buf.WriteString("=")
		buf.WriteString(l.Value)
	}
}

// IsValid returns true if Key != "".
func (l *Label) IsValid() bool {
	return l.Key != ""
}

// UnmarshalJSON TODO create better explanation about unmarshall with examples
func (l *Label) UnmarshalJSON(data []byte) error {
	if l == nil {
		return fmt.Errorf("cannot unmarshal to nil pointer")
	}

	if len(data) == 0 {
		return fmt.Errorf("invalid Label: empty data")
	}

	var aux struct {
		Source string `json:"source"`
		Key    string `json:"key"`
		Value  string `json:"value,omitempty"`
	}

	err := json.Unmarshal(data, &aux)
	if err != nil {
		// If parsing of the full representation failed then try the short
		// form in the format:
		//
		// [SOURCE:]KEY[=VALUE]
		var aux string

		if err := json.Unmarshal(data, &aux); err != nil {
			return fmt.Errorf("decode of Label as string failed: %w", err)
		}

		if aux == "" {
			return fmt.Errorf("invalid Label: Failed to parse %s as a string", data)
		}

		*l = ParseLabel(aux)
	} else {
		if aux.Key == "" {
			return fmt.Errorf("invalid Label: '%s' does not contain label key", data)
		}

		l.Source = aux.Source
		l.Key = aux.Key
		l.Value = aux.Value
	}

	if l.Source == LabelSourceCIDR {
		c, err := LabelToPrefix(l.Key)
		if err == nil {
			l.cidr = &c
		} else {
			// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
			logging.DefaultSlogLogger.Error("Failed to parse CIDR label: invalid prefix.",
				logfields.Error, err,
				logfields.Key, l.Key,
			)
		}
	}

	return nil
}

// GetExtendedKey returns the key of a label with the source encoded.
func (l *Label) GetExtendedKey() string {
	return l.Source + PathDelimiter + l.Key
}

// GetCiliumKeyFrom returns the label's source and key from the an extended key
// in the format SOURCE:KEY.
func GetCiliumKeyFrom(extKey string) string {
	i := strings.IndexByte(extKey, PathDelimiter[0])
	if i >= 0 {
		return extKey[:i] + ":" + extKey[i+1:]
	}
	return LabelSourceAny + ":" + extKey
}

// GetExtendedKeyFrom returns the extended key of a label string.
// For example:
// `k8s:foo=bar` returns `k8s.foo`
// `container:foo=bar` returns `container.foo`
// `foo=bar` returns `any.foo=bar`
func GetExtendedKeyFrom(str string) string {
	src, next := parseSource(str, ':')
	if src == "" {
		src = LabelSourceAny
	}
	// Remove an eventually value
	i := strings.IndexByte(next, '=')
	if i >= 0 {
		return src + PathDelimiter + next[:i]
	}
	return src + PathDelimiter + next
}

type KeyExtender func(string) string

// Extender to convert label keys from Cilium representation to kubernetes representation.
// Key passed to this extender is converted to format `<source>.<key>`.
// The extender is not idempotent, caller needs to make sure its only called once for a key.
var DefaultKeyExtender KeyExtender = GetExtendedKeyFrom

func GetSourcePrefixKeyExtender(srcPrefix string) KeyExtender {
	return func(str string) string {
		return srcPrefix + str
	}
}

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels. The
// source argument will overwrite the source written in the key of the given map.
// Example:
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "cilium")
// fmt.Printf("%+v\n", l)
//
//	map[string]Label{"foo":Label{Key:"foo", Value:"bar", Source:"cilium"}}
func Map2Labels(m map[string]string, source string) Labels {
	o := make(Labels, len(m))
	for k, v := range m {
		l := NewLabel(k, v, source)
		o[l.Key] = l
	}
	return o
}

// StringMap converts Labels into map[string]string
func (l Labels) StringMap() map[string]string {
	o := make(map[string]string, len(l))
	for _, v := range l {
		o[v.Source+":"+v.Key] = v.Value
	}
	return o
}

// StringMap converts Labels into map[string]string
func (l Labels) K8sStringMap() map[string]string {
	o := make(map[string]string, len(l))
	for _, v := range l {
		if v.Source == LabelSourceK8s || v.Source == LabelSourceAny || v.Source == LabelSourceUnspec {
			o[v.Key] = v.Value
		} else {
			o[v.Source+"."+v.Key] = v.Value
		}
	}
	return o
}

// NewLabelsFromModel creates labels from string array.
func NewLabelsFromModel(base []string) Labels {
	lbls := make(Labels, len(base))
	for _, v := range base {
		if lbl := ParseLabel(v); lbl.Key != "" {
			lbls[lbl.Key] = lbl
		}
	}

	return lbls
}

// FromSlice creates labels from a slice of labels.
func FromSlice(labels []Label) Labels {
	lbls := make(Labels, len(labels))
	for _, lbl := range labels {
		lbls[lbl.Key] = lbl
	}
	return lbls
}

// NewLabelsFromSortedList returns labels based on the output of SortedList()
func NewLabelsFromSortedList(list string) Labels {
	return NewLabelsFromModel(strings.Split(list, ";"))
}

// NewFrom creates a new Labels from the given labels by creating a copy.
func NewFrom(l Labels) Labels {
	nl := make(Labels, len(l))
	nl.MergeLabels(l)
	return nl
}

// GetModel returns model with all the values of the labels.
func (l Labels) GetModel() []string {
	res := make([]string, 0, len(l))
	for _, v := range l {
		res = append(res, v.String())
	}
	return res
}

// MergeLabels merges labels from into to. It overwrites all labels with the same Key as
// from written into to.
// Example:
// to := Labels{Label{key1, value1, source1}, Label{key2, value3, source4}}
// from := Labels{Label{key1, value3, source4}}
// to.MergeLabels(from)
// fmt.Printf("%+v\n", to)
//
//	Labels{Label{key1, value3, source4}, Label{key2, value3, source4}}
func (l Labels) MergeLabels(from Labels) {
	maps.Copy(l, from)
}

// Remove is similar to MergeLabels, but removes the specified Labels from l.
// The received Labels is not modified.
func (l Labels) Remove(from Labels) {
	maps.DeleteFunc(l, func(k string, v Label) bool {
		_, exists := from[k]
		return exists
	})
}

// FormatForKVStore returns the label as a formatted string, ending in
// a semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS
// PART OF THE KEY IN THE KEY-VALUE STORE.
//
// Non-pointer receiver allows this to be called on a value in a map.
func (l Label) FormatForKVStore() []byte {
	// We don't care if the values already have a '='.
	//
	// We absolutely care that the final character is a semi-colon.
	// Identity allocation in the kvstore depends on this (see
	// kvstore.prefixMatchesKey())
	b := make([]byte, 0, len(l.Source)+len(l.Key)+len(l.Value)+3)
	buf := bytes.NewBuffer(b)
	l.formatForKVStoreInto(buf)
	return buf.Bytes()
}

// formatForKVStoreInto writes the label as a formatted string, ending in
// a semicolon into buf.
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS
// PART OF THE KEY IN THE KEY-VALUE STORE.
//
// Non-pointer receiver allows this to be called on a value in a map.
func (l Label) formatForKVStoreInto(buf *bytes.Buffer) {
	buf.WriteString(l.Source)
	buf.WriteRune(':')
	buf.WriteString(l.Key)
	buf.WriteRune('=')
	buf.WriteString(l.Value)
	buf.WriteRune(';')
}

// SortedList returns the labels as a sorted list, separated by semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS KEY IN
// THE KEY-VALUE STORE.
func (l Labels) SortedList() []byte {
	keys := slices.Sorted(maps.Keys(l))

	// Labels can have arbitrary size. However, when many CIDR identities are in
	// the system, for example due to a FQDN policy matching S3, CIDR labels
	// dominate in number. IPv4 CIDR labels in serialized form are max 25 bytes
	// long. Allocate slightly more to avoid having a realloc if there's some
	// other labels which may longer, since the cost of allocating a few bytes
	// more is dominated by a second allocation, especially since these
	// allocations are short-lived.
	//
	// cidr:123.123.123.123/32=;
	// 0        1         2
	// 1234567890123456789012345
	b := make([]byte, 0, len(keys)*30)
	buf := bytes.NewBuffer(b)
	for _, k := range keys {
		l[k].formatForKVStoreInto(buf)
	}

	return buf.Bytes()
}

// ToSlice returns a slice of label with the values of the given
// Labels' map, sorted by the key.
func (l Labels) ToSlice() []Label {
	return l.LabelArray()
}

// LabelArray returns the labels as label array, sorted by the key.
func (l Labels) LabelArray() LabelArray {
	labels := make(LabelArray, 0, len(l))
	for _, v := range l {
		labels = append(labels, v)
	}
	return labels.Sort()
}

// FindReserved locates all labels with reserved source in the labels and
// returns a copy of them. If there are no reserved labels, returns nil.
func (l Labels) FindReserved() LabelArray {
	lbls := make(LabelArray, 0)

	for _, lbl := range l {
		if lbl.Source == LabelSourceReserved {
			lbls = append(lbls, lbl)
		}
	}

	if len(lbls) > 0 {
		return lbls
	}
	return nil
}

// IsReserved returns true if any of the labels has a reserved source.
func (l Labels) IsReserved() bool {
	return l.HasSource(LabelSourceReserved)
}

// Has returns true if l contains the given label.
func (l Labels) Has(label Label) bool {
	for _, lbl := range l {
		if lbl.Has(&label) {
			return true
		}
	}
	return false
}

// HasSource returns true if l contains the given label source.
func (l Labels) HasSource(source string) bool {
	for _, lbl := range l {
		if lbl.Source == source {
			return true
		}
	}
	return false
}

// CollectSources returns all distinct label sources found in l
func (l Labels) CollectSources() map[string]struct{} {
	sources := make(map[string]struct{})
	for _, lbl := range l {
		sources[lbl.Source] = struct{}{}
	}
	return sources
}

// parseSource returns the parsed source of the given str. It also returns the next piece
// of text that is after the source.
// Example:
//
//	src, next := parseSource("foo:bar==value")
//
// Println(src) // foo
// Println(next) // bar==value
// For Cilium format 'delim' must be passed in as ':'
// For k8s format 'delim' must be passed in as '.'
func parseSource(str string, delim byte) (src, next string) {
	if str == "" {
		return "", ""
	}
	if str[0] == '$' {
		return LabelSourceReserved, str[1:]
	}
	i := strings.IndexByte(str, delim)
	if i < 0 {
		if delim != '.' && strings.HasPrefix(str, LabelSourceReservedKeyPrefix) {
			return LabelSourceReserved, strings.TrimPrefix(str, LabelSourceReservedKeyPrefix)
		}
		return "", str
	}
	return str[:i], str[i+1:]
}

// ParseLabel returns the label representation of the given string. The str should be
// in the form of Source:Key=Value or Source:Key if Value is empty. It also parses short
// forms, for example: $host will be Label{Key: "host", Source: "reserved", Value: ""}.
func ParseLabel(str string) Label {
	return parseLabel(str, ':')
}

// parseLabel returns the label representation of the given string by value.
// For Cilium format 'delim' must be passed in as ':'
// For k8s format 'delim' must be passed in as '.'
func parseLabel(str string, delim byte) (lbl Label) {
	src, next := parseSource(str, delim)
	if src != "" {
		lbl.Source = src
	} else {
		lbl.Source = LabelSourceUnspec
	}

	i := strings.IndexByte(next, '=')
	if i < 0 {
		lbl.Key = next
	} else {
		if i == 0 && src == LabelSourceReserved {
			lbl.Key = next[i+1:]
		} else {
			lbl.Key = next[:i]
			lbl.Value = next[i+1:]
		}
	}

	if lbl.Source == LabelSourceCIDR {
		if lbl.Value != "" {
			// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
			logging.DefaultSlogLogger.Error("Invalid CIDR label: labels with source cidr cannot have values.",
				logfields.Label, lbl,
			)
		}
		c, err := LabelToPrefix(lbl.Key)
		if err != nil {
			// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
			logging.DefaultSlogLogger.Error("Failed to parse CIDR label: invalid prefix.",
				logfields.Label, lbl,
			)
		} else {
			lbl.cidr = &c
		}
	}
	return lbl
}

// ParseSelectLabel returns a selecting label representation of the given
// string. Unlike ParseLabel, if source is unspecified, the source defaults to
// LabelSourceAny
func ParseSelectLabel(str string) Label {
	return parseSelectLabel(str, ':')
}

// parseSelectLabel returns a selecting label representation of the given
// string by value.
// For Cilium format 'delim' must be passed in as ':'
// For k8s format 'delim' must be passed in as '.'
func parseSelectLabel(str string, delim byte) Label {
	lbl := parseLabel(str, delim)

	if lbl.Source == LabelSourceUnspec {
		lbl.Source = LabelSourceAny
	}

	return lbl
}

// generateLabelString generates the string representation of a label with
// the provided source, key, and value in the format "source:key=value".
func generateLabelString(source, key, value string) string {
	return source + ":" + key + "=" + value
}

// GenerateK8sLabelString generates the string representation of a label with
// the provided source, key, and value in the format "LabelSourceK8s:key=value".
func GenerateK8sLabelString(k, v string) string {
	return generateLabelString(LabelSourceK8s, k, v)
}
