//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package labelsfilter

// AppendPodLabelPrefixes appends the provided prefixes to the pod label prefixes,
// for instance to allowlist enterprise-only labels. This function is intended to
// be invoked from either Provide or Invoke functions.
func AppendPodLabelPrefixes(prefixes ...string) error {
	return appendLabelPrefixes(validLabelPrefixes, prefixes...)
}

// AppendNodeLabelPrefixes appends the provided prefixes to the node label prefixes,
// for instance to allowlist enterprise-only labels. This function is intended to
// be invoked from either Provide or Invoke functions.
func AppendNodeLabelPrefixes(prefixes ...string) error {
	return appendLabelPrefixes(validNodeLabelPrefixes, prefixes...)
}

func appendLabelPrefixes(target *labelPrefixCfg, prefixes ...string) error {
	validLabelPrefixesMU.Lock()
	defer validLabelPrefixesMU.Unlock()

	// The target prefix configuration is not initialized in integration tests.
	if target == nil {
		return nil
	}

	for _, label := range prefixes {
		lp, err := parseLabelPrefix(label)
		if err != nil {
			return err
		}

		target.LabelPrefixes = append(target.LabelPrefixes, lp)
	}

	return nil
}
