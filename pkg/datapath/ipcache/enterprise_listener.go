//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipcache

import (
	"slices"

	"github.com/cilium/cilium/pkg/bpf"
)

// ChainableMap allows enterprise wrappers to compose on top of the current
// ipcache map rather than replacing the previously injected one.
type ChainableMap interface {
	Map
	SetNext(Map)
}

type mapChain struct {
	orig Map

	// overrides in the reverse order, overrides[0] is the
	// last one called before [orig].
	overrides []ChainableMap
}

// Delete implements [Map].
func (mc *mapChain) Delete(key bpf.MapKey) error {
	if len(mc.overrides) == 0 {
		return mc.orig.Delete(key)
	}
	return mc.overrides[len(mc.overrides)-1].Delete(key)
}

// Update implements [Map].
func (mc *mapChain) Update(key bpf.MapKey, value bpf.MapValue) error {
	if len(mc.overrides) == 0 {
		return mc.orig.Update(key, value)
	}
	return mc.overrides[len(mc.overrides)-1].Update(key, value)
}

// rebuild the override chain
func (mc *mapChain) rebuild() {
	m := mc.orig
	for _, override := range mc.overrides {
		override.SetNext(m)
		m = override
	}
}

// prepend adds an override that should be called early
func (mc *mapChain) prepend(m ChainableMap) {
	mc.overrides = append(mc.overrides, m)
	mc.rebuild()
}

// append adds an override that should be called late
func (mc *mapChain) append(m ChainableMap) {
	mc.overrides = slices.Insert(mc.overrides, 0, m)
	mc.rebuild()
}

var _ Map = &mapChain{}

// InjectCEMap allows to override the default ipcache map interface injected
// through hive to possibly mutate the key/value pair to support additional
// enterprise features (e.g., mixed routing mode). This method is intended to
// be executed through an Invoke function.
func InjectCEMap(l *BPFListener, override ChainableMap) {
	if mc, ok := l.bpfMap.(*mapChain); ok {
		mc.prepend(override)
		return
	}
	mc := &mapChain{orig: l.bpfMap}
	mc.prepend(override)
	l.bpfMap = mc
}

// InjectCEMapLate is like [InjectCEMap] except this override will be later
// in the chain than any override added by [InjectCEMap].
func InjectCEMapLate(l *BPFListener, override ChainableMap) {
	if mc, ok := l.bpfMap.(*mapChain); ok {
		mc.append(override)
		return
	}
	mc := &mapChain{orig: l.bpfMap}
	mc.append(override)
	l.bpfMap = mc
}
