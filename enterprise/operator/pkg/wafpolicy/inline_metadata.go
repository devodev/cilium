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
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

type inlineMetadata struct {
	Policies []string `json:"policies"`
}

func parseInlineMetadata(raw string) (inlineMetadata, error) {
	var metadata inlineMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return inlineMetadata{}, err
	}
	return metadata, nil
}

func marshalInlineMetadata(metadata inlineMetadata) (string, error) {
	sort.Strings(metadata.Policies)
	metadata.Policies = slices.Compact(metadata.Policies)

	raw, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func upsertInlineMetadata(data map[string]string, hashKey, policyRef string) (map[string]string, error) {
	if data == nil {
		data = map[string]string{}
	}

	metadata := inlineMetadata{}
	if raw, ok := data[hashKey]; ok {
		var err error
		metadata, err = parseInlineMetadata(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse inline metadata for %q: %w", hashKey, err)
		}
	}

	metadata.Policies = append(metadata.Policies, policyRef)
	raw, err := marshalInlineMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inline metadata for %q: %w", hashKey, err)
	}
	data[hashKey] = raw
	return data, nil
}

func removePolicyFromMetadata(data map[string]string, hashKey, policyRef string) (map[string]string, bool, error) {
	raw, ok := data[hashKey]
	if !ok {
		return data, false, nil
	}

	metadata, err := parseInlineMetadata(raw)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse inline metadata for %q: %w", hashKey, err)
	}

	filtered := metadata.Policies[:0]
	for _, policy := range metadata.Policies {
		if policy != policyRef {
			filtered = append(filtered, policy)
		}
	}
	if len(filtered) == 0 {
		delete(data, hashKey)
		return data, true, nil
	}

	metadata.Policies = filtered
	raw, err = marshalInlineMetadata(metadata)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal inline metadata for %q: %w", hashKey, err)
	}
	data[hashKey] = raw
	return data, false, nil
}
