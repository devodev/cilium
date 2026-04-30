//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"maps"
	"strings"
)

const (
	inlineRulePrefix     = "rules."
	inlineMetadataPrefix = "meta."
)

func reconcileInlineBundleState(
	existing map[string]string,
	policyRef, desiredHashKey string,
	desiredInline string,
) (map[string]string, error) {
	metadata := extractInlineMetadata(existing)
	metadata, hashesToDelete, err := reconcileInlineMetadata(metadata, policyRef, desiredHashKey)
	if err != nil {
		return nil, err
	}

	inlineRules := extractInlineRules(existing)
	pruneInlineRules(inlineRules, hashesToDelete)
	if inlineRules == nil && desiredHashKey != "" {
		inlineRules = map[string]string{}
	}
	if desiredHashKey != "" {
		inlineRules[desiredHashKey] = desiredInline
	}
	pruneOrphanInlineRules(inlineRules, metadata)

	return combineInlineBundleData(metadata, inlineRules), nil
}

// reconcileInlineMetadata updates metadata ownership for a single policy
// reconcile pass. It first removes the policy reference from every stale hash,
// then upserts the reference into the desired hash. The returned delete set
// contains inline rule hashes whose metadata entries lost their last policy
// reference and can therefore be pruned from the inline rules ConfigMap.
func reconcileInlineMetadata(existing map[string]string, policyRef, desiredHashKey string) (map[string]string, map[string]struct{}, error) {
	data := maps.Clone(existing)
	hashesToDelete := map[string]struct{}{}

	for hashKey := range maps.Clone(data) {
		if hashKey == desiredHashKey {
			continue
		}
		updated, deleted, err := removePolicyFromMetadata(data, hashKey, policyRef)
		if err != nil {
			return nil, nil, err
		}
		data = updated
		if deleted {
			hashesToDelete[hashKey] = struct{}{}
		}
	}

	if desiredHashKey != "" {
		updated, err := upsertInlineMetadata(data, desiredHashKey, policyRef)
		if err != nil {
			return nil, nil, err
		}
		data = updated
		delete(hashesToDelete, desiredHashKey)
	}

	return normalizeConfigMapData(data), hashesToDelete, nil
}

func extractInlineMetadata(data map[string]string) map[string]string {
	metadata := map[string]string{}
	for key, value := range data {
		if hashKey, ok := strings.CutPrefix(key, inlineMetadataPrefix); ok {
			metadata[hashKey] = value
		}
	}
	return normalizeConfigMapData(metadata)
}

func extractInlineRules(data map[string]string) map[string]string {
	inlineRules := map[string]string{}
	for key, value := range data {
		if hashKey, ok := strings.CutPrefix(key, inlineRulePrefix); ok {
			inlineRules[hashKey] = value
		}
	}
	return normalizeConfigMapData(inlineRules)
}

func pruneInlineRules(data map[string]string, hashesToDelete map[string]struct{}) {
	for hashKey := range hashesToDelete {
		delete(data, hashKey)
	}
}

func pruneOrphanInlineRules(rules, metadata map[string]string) {
	for hashKey := range maps.Clone(rules) {
		if _, ok := metadata[hashKey]; !ok {
			delete(rules, hashKey)
		}
	}
}

func combineInlineBundleData(metadata, rules map[string]string) map[string]string {
	if len(metadata) == 0 && len(rules) == 0 {
		return nil
	}

	data := map[string]string{}
	for hashKey, raw := range metadata {
		data[inlineMetadataPrefix+hashKey] = raw
	}
	for hashKey, inline := range rules {
		data[inlineRulePrefix+hashKey] = inline
	}

	return data
}

func normalizeConfigMapData(data map[string]string) map[string]string {
	if len(data) == 0 {
		return nil
	}
	return data
}
