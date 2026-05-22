//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"bytes"
	"cmp"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/cilium/enterprise/features"
)

// Helm feature-gate validation template generator.
// Generates the file 'install/kubernetes/cilium/templates/enterprise_features_validate.yaml"
// via the make target in 'install/kubernetes/Makefile.override'.
func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "generate":
		generate()
	case "validate":
		validate()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: helm-gen (generate|validate)\n")
	os.Exit(1)
}

// generate a helm validation template from features.yaml for the feature gates. The template is written
// to stdout.
func generate() {
	validGates := make([]string, 0, len(features.FeaturesYaml.Features))
	for id := range features.FeaturesYaml.Features {
		validGates = append(validGates, id)
	}
	sort.Strings(validGates)

	stable := features.FeaturesYaml.Levels[0].Name
	unstableFeatures := map[string]features.YAMLFeature{}
	for id, feat := range features.FeaturesYaml.Features {
		if feat.Maturity != stable && (len(feat.Helm) > 0 || len(feat.HelmCheck) > 0) {
			unstableFeatures[id] = feat
		}
	}

	// levels maps maturity level to order number
	levels := map[string]int{}
	for i, level := range features.FeaturesYaml.Levels {
		levels[level.Name] = i
	}

	t := template.Must(template.New("validate").Parse(validateTemplate))
	var buf bytes.Buffer
	err := t.Execute(&buf, data{
		ValidFeatureGates:    validGates,
		Levels:               levels,
		UnstableFeatures:     unstableFeatures,
		MinimumMaturityOrder: 0,
		HelmConds:            generateConds(features.FeaturesYaml.Features),
	})
	if err != nil {
		panic(err)
	}
	out := strings.ReplaceAll(buf.String(), "[[", "{{")
	out = strings.ReplaceAll(out, "]]", "}}")
	out = html.UnescapeString(out) // Undo HTML escaping. Thanks text/template!
	os.Stdout.Write([]byte(out))
}

// validate the generated template by executing "helm template" for each feature.
// For each feature we run helm template first with the enable options but without
// approving the feature to check it fails, and then we run it with the approval to
// check it passes.
//
// All "helm template" calls are executed in parallel to speed this up as each call
// takes about 300ms.
func validate() {
	helmProg, err := exec.LookPath("helm")
	if err != nil {
		log.Fatal(err)
	}

	defArgs := []string{
		"template",
		"cilium", // This is intended to run from install/kubernetes.
	}

	defSets := []string{
		"enterprise.featureGate.strict=true",
	}

	type result struct {
		id  string
		err error
	}
	results := make(chan result, 1)

	for id, feat := range features.FeaturesYaml.Features {
		go func() {
			if feat.Maturity == "Stable" || len(feat.Helm) == 0 {
				results <- result{id, nil}
				return
			}
			opts := []string{}
			for k, v := range feat.Helm {
				opts = append(opts, fmt.Sprintf("%s=%s", k, v))
			}

			for k, v := range feat.HelmTestDeps {
				opts = append(opts, fmt.Sprintf("%s=%s", k, v))
			}

			// Test without allowing the feature.
			cmd := exec.Command(helmProg,
				append(defArgs,
					"--set",
					strings.Join(slices.Concat(defSets, opts), ","))...)
			cmd.Stdout = io.Discard
			var buf bytes.Buffer
			cmd.Stderr = &buf
			if err := cmd.Run(); err == nil {
				results <- result{
					id,
					fmt.Errorf("expected %s to fail when approved (%s)", id, buf.String()),
				}
				return
			}

			cmd = exec.Command(helmProg,
				append(defArgs,
					"--set",
					strings.Join(
						slices.Concat(
							defSets,
							opts,
							[]string{"enterprise.featureGate.approved={" + id + "}"}),
						",",
					),
				)...)
			cmd.Stdout = io.Discard
			buf = bytes.Buffer{}
			cmd.Stderr = &buf
			if err := cmd.Run(); err != nil {
				fmt.Printf("command: %s\n", cmd)
				results <- result{
					id,
					fmt.Errorf("expected %s to succeed when approved: %w (%s)", id, err, buf.String()),
				}
				return
			}
			results <- result{id, nil}
		}()
	}

	for range features.FeaturesYaml.Features {
		r := <-results
		if r.err != nil {
			fmt.Printf("\nFAIL: %s: %s\n", r.id, r.err)
			fmt.Println("Test failed.")
			os.Exit(1)
		}
		fmt.Printf("%s ", r.id)
	}
	fmt.Println()
	fmt.Println("Test passed.")
}

func generateConds(feats map[string]features.YAMLFeature) map[string]string {
	conds := map[string]string{}
	for id, feat := range feats {
		if len(feat.HelmCheck) > 0 {
			conds[id] = feat.HelmCheck
		} else if len(feat.Helm) > 0 {
			conds[id] = generateCond(feat.Helm)
		}
	}
	return conds
}

func generateCond(opts map[string]string) string {
	var b strings.Builder
	if len(opts) > 1 {
		b.WriteString("(and ")
	}
	inOrder(opts, func(k string, v string) {
		fmt.Fprintf(&b, "(eq %q (print .%s)) ", v, k)
	})
	if len(opts) > 1 {
		b.WriteString(")")
	}
	return b.String()
}

// TODO: Redo this with iter.Seq once isovalent/cilium is Go v1.23
func inOrder[K cmp.Ordered, V any](m map[K]V, fn func(K, V)) {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fn(k, m[k])
	}
}

type data struct {
	MinimumMaturityOrder int
	ValidFeatureGates    []string
	UnstableFeatures     map[string]features.YAMLFeature
	Levels               map[string]int
	HelmConds            map[string]string
}

// This template generates into templates/enterprise_features_validate.yaml.
// The 'enterprise.validateFeatures' is referenced from NOTES.txt and output
// from this template will appear at the end of the "helm install/upgrade"
// invocation.
//
// Since we're dealing with two levels of Go text templating, we'll use
// [[ and ]] for the inner helm template escaping. After template is rendered
// these are substituted back to {{ and }}.
var validateTemplate = `[[- /*Auto-generated by features/helm-gen. Do not edit by hand.*/ -]]
[[- define "enterprise.validateFeatures" ]]
{{- $helmConds := .HelmConds -}}
[[- $featureMaturityLevels := dict {{range $name, $ord := .Levels}}"{{ $name }}" {{ $ord }} {{end}} ]]
[[- $validFeatureGates := list {{range .ValidFeatureGates}}"{{ . }}" {{end}} ]]
[[- range .enterprise.featureGate.approved -]]
[[- if not (has . $validFeatureGates) -]]
  [[- fail (printf "Invalid feature gate exception %q" .) ]]
[[- end -]]
[[- end -]]
[[- $minimumMaturityOrder := 0 -]]
[[- if hasKey .enterprise.featureGate "minimumMaturity" -]]
[[- $minimumMaturityOrder = get $featureMaturityLevels .enterprise.featureGate.minimumMaturity -]]
[[- end -]]
[[- $strictFeatureGates := .enterprise.featureGate.strict -]]
[[- $fails := false -]]
{{- range $id, $feat := .UnstableFeatures}}
[[- if {{ index $helmConds $id }} -]]
  [[- if (and (gt (get $featureMaturityLevels "{{$feat.Maturity}}") $minimumMaturityOrder) (not (has "{{$id}}" .enterprise.featureGate.approved))) -]]
    [[- if $strictFeatureGates -]]
      [[- fail "\n{{$feat.Maturity}} feature: {{$id}} was enabled, but is not an approved feature. Please contact Isovalent Support for more information on how to grant an exception." -]]
    [[- else -]]
      [[ $fails = true ]]
WARNING: A {{$feat.Maturity}} feature {{$id}} was enabled, but it is not an approved feature.
    [[- end -]]
  [[- end -]]
[[- end -]]
{{- end -}}
[[- if $fails ]]
Please contact Isovalent Support for more information on how to grant an exception.
[[- end ]]
[[- end ]]
`
