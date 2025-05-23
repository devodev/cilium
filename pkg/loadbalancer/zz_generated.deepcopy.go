//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package loadbalancer

import (
	cidr "github.com/cilium/cilium/pkg/cidr"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L3n4Addr) DeepCopyInto(out *L3n4Addr) {
	*out = *in
	in.AddrCluster.DeepCopyInto(&out.AddrCluster)
	out.L4Addr = in.L4Addr
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L3n4Addr.
func (in *L3n4Addr) DeepCopy() *L3n4Addr {
	if in == nil {
		return nil
	}
	out := new(L3n4Addr)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L3n4AddrID) DeepCopyInto(out *L3n4AddrID) {
	*out = *in
	in.L3n4Addr.DeepCopyInto(&out.L3n4Addr)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L3n4AddrID.
func (in *L3n4AddrID) DeepCopy() *L3n4AddrID {
	if in == nil {
		return nil
	}
	out := new(L3n4AddrID)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L4Addr) DeepCopyInto(out *L4Addr) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L4Addr.
func (in *L4Addr) DeepCopy() *L4Addr {
	if in == nil {
		return nil
	}
	out := new(L4Addr)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LegacyBackend) DeepCopyInto(out *LegacyBackend) {
	*out = *in
	in.L3n4Addr.DeepCopyInto(&out.L3n4Addr)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LegacyBackend.
func (in *LegacyBackend) DeepCopy() *LegacyBackend {
	if in == nil {
		return nil
	}
	out := new(LegacyBackend)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LegacySVC) DeepCopyInto(out *LegacySVC) {
	*out = *in
	in.Frontend.DeepCopyInto(&out.Frontend)
	if in.Backends != nil {
		in, out := &in.Backends, &out.Backends
		*out = make([]*LegacyBackend, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(LegacyBackend)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	out.Name = in.Name
	if in.LoadBalancerSourceRanges != nil {
		in, out := &in.LoadBalancerSourceRanges, &out.LoadBalancerSourceRanges
		*out = make([]*cidr.CIDR, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = (*in).DeepCopy()
			}
		}
	}
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LegacySVC.
func (in *LegacySVC) DeepCopy() *LegacySVC {
	if in == nil {
		return nil
	}
	out := new(LegacySVC)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceName) DeepCopyInto(out *ServiceName) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceName.
func (in *ServiceName) DeepCopy() *ServiceName {
	if in == nil {
		return nil
	}
	out := new(ServiceName)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SvcFlagParam) DeepCopyInto(out *SvcFlagParam) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SvcFlagParam.
func (in *SvcFlagParam) DeepCopy() *SvcFlagParam {
	if in == nil {
		return nil
	}
	out := new(SvcFlagParam)
	in.DeepCopyInto(out)
	return out
}
