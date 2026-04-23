// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package check

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/internal/junit"
	"github.com/cilium/cilium/tools/testowners/codeowners"
)

// EnterpriseJUnitParams configures JUnit generation for enterprise test runners.
type EnterpriseJUnitParams struct {
	JunitFile         string
	JunitProperties   map[string]string
	CodeOwners        []string
	LogCodeOwners     bool
	ExcludeCodeOwners []string
}

// EnterpriseJUnitCollector collects JUnit results for enterprise test suites.
type EnterpriseJUnitCollector struct {
	className      string
	params         EnterpriseJUnitParams
	testSuite      *junit.TestSuite
	workflowOwners []string
}

// NewEnterpriseJUnitCollector returns a JUnit collector for non-connectivity enterprise test runners.
func NewEnterpriseJUnitCollector(suiteName string, params EnterpriseJUnitParams) (*EnterpriseJUnitCollector, error) {
	c := &EnterpriseJUnitCollector{
		className: suiteName,
		params:    params,
		testSuite: &junit.TestSuite{
			Name:       suiteName,
			Package:    "cilium",
			Properties: &junit.Properties{},
		},
	}
	for _, key := range slices.Sorted(maps.Keys(params.JunitProperties)) {
		c.testSuite.Properties.Properties = append(c.testSuite.Properties.Properties, junit.Property{
			Name:  key,
			Value: params.JunitProperties[key],
		})
	}
	wfOwners, err := enterpriseWorkflowOwners(params.CodeOwners, params.ExcludeCodeOwners)
	if err != nil {
		return nil, err
	}
	for _, owner := range wfOwners {
		c.testSuite.Properties.Properties = append(c.testSuite.Properties.Properties, junit.Property{
			Name:  "owner",
			Value: owner,
		})
		c.workflowOwners = append(c.workflowOwners, owner)
	}
	return c, nil
}

func enterpriseWorkflowOwners(codeOwnersPaths, excludeOwners []string) ([]string, error) {
	if len(codeOwnersPaths) == 0 {
		return nil, nil
	}
	owners, err := codeowners.Load(codeOwnersPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load code owners: %w", err)
	}
	if len(excludeOwners) > 0 {
		owners = owners.WithExcludedOwners(excludeOwners)
	}
	workflowOwners, err := owners.WorkflowOwners(false)
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow owners: %w", err)
	}
	return workflowOwners, nil
}

// CollectTest collects a single test result.
func (j *EnterpriseJUnitCollector) CollectTest(name string, startedAt, completedAt time.Time, err error) {
	if j.params.JunitFile == "" {
		return
	}
	if completedAt.Before(startedAt) {
		completedAt = startedAt
	}
	if j.testSuite.Timestamp == "" {
		j.testSuite.Timestamp = startedAt.Format(time.RFC3339)
	}

	test := &junit.TestCase{
		Name:      name,
		Classname: j.className,
		Status:    "passed",
		Time:      completedAt.Sub(startedAt).Seconds(),
	}
	j.testSuite.Tests++
	j.testSuite.Time += test.Time

	if err != nil {
		test.Status = "failed"
		test.Failure = &junit.Failure{
			Message: name + " failed",
			Type:    "failure",
			Value:   err.Error(),
		}
		j.testSuite.Failures++
	}
	j.testSuite.TestCases = append(j.testSuite.TestCases, test)
}

// CollectSkippedTest collects a skipped test result.
func (j *EnterpriseJUnitCollector) CollectSkippedTest(name, message string) {
	if j.params.JunitFile == "" {
		return
	}
	if j.testSuite.Timestamp == "" {
		j.testSuite.Timestamp = time.Now().Format(time.RFC3339)
	}

	test := &junit.TestCase{
		Name:      name,
		Classname: j.className,
		Status:    "skipped",
		Time:      0,
		Skipped: &junit.Skipped{
			Message: message,
		},
	}
	j.testSuite.Tests++
	j.testSuite.Skipped++
	j.testSuite.TestCases = append(j.testSuite.TestCases, test)
}

// Write writes collected JUnit results into a single report file.
func (j *EnterpriseJUnitCollector) Write() error {
	if j.testSuite.Tests == 0 {
		return nil
	}

	suites := junit.TestSuites{
		Tests:      j.testSuite.Tests,
		Disabled:   j.testSuite.Skipped,
		Failures:   j.testSuite.Failures,
		Time:       j.testSuite.Time,
		TestSuites: []*junit.TestSuite{j.testSuite},
	}
	f, err := os.Create(j.params.JunitFile)
	if err != nil {
		return err
	}

	if err := suites.WriteReport(f); err != nil {
		defer os.Remove(j.params.JunitFile)
		if closeErr := f.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}
	return f.Close()
}

func (j *EnterpriseJUnitCollector) LogCodeOwnersIfNeeded(w io.Writer) {
	if w == nil {
		return
	}
	if !j.params.LogCodeOwners {
		return
	}
	if j.testSuite.Errors == 0 && j.testSuite.Failures == 0 {
		return
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    ⛑️ The following owners are responsible for reliability of the testsuite: ")
	for _, owner := range j.workflowOwners {
		fmt.Fprintln(w, "        - "+owner)
	}
	fmt.Fprintln(w, "")
}
