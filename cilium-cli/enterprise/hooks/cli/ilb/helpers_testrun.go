//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

type lbTestRun struct {
	ciliumNamespace string
	ipv4Enabled     bool
	ipv6Enabled     bool
	cleanupCb       []func(ctx context.Context) error
}

func NewLBTestRun(ctx context.Context, ciliumNamespace string) *lbTestRun {
	return &lbTestRun{
		ciliumNamespace: ciliumNamespace,
		cleanupCb:       []func(ctx context.Context) error{},
	}
}

func (r *lbTestRun) SetIPInfo(ipv4Enabled bool, ipv6Enabled bool) {
	r.ipv4Enabled = ipv4Enabled
	r.ipv6Enabled = ipv6Enabled
}

func (r *lbTestRun) ExecuteTestFuncs(ctx context.Context) error {
	testsToExecute, err := r.testsToExecute(ctx)
	if err != nil {
		return err
	}

	wg := sync.WaitGroup{}
	totalTests := len(testsToExecute)
	failedTests := 0
	for i, test := range testsToExecute {
		select {
		case <-ctx.Done():
			fmt.Println("Cancelled - stopping test execution...")
			return nil
		default:
			fmt.Printf("=== [%02d/%02d] %s\n", i+1, totalTests, test.Name())
			var finished bool
			wg.Go(func() {
				test.Run()
				finished = true
			})
			wg.Wait()

			if (!finished || test.failed) && !FlagContinueOnFailure {
				return fmt.Errorf("❌ %s test failed", test.Name())
			}

			if test.failed {
				failedTests++
			}

			if FlagVerbose {
				// newline to highlight start of new test function in verbose mode
				fmt.Println()
			}
		}
	}

	if failedTests > 0 {
		return fmt.Errorf("❌ %d/%d tests failed", failedTests, totalTests)
	}

	fmt.Printf("✅ All %d tests successful.\n", totalTests)
	return nil
}

func (r *lbTestRun) Failedf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nILB testrun failed with error: %s\n", fmt.Sprintf(msg, args...))
	r.Failed()
}

func (r *lbTestRun) Failed() {
	runtime.Goexit()
}

// RegisterCleanup registers a cleanup that gets executed when the testrun ends.
func (r *lbTestRun) RegisterCleanup(f func(ctx context.Context) error) {
	r.cleanupCb = append(r.cleanupCb, f)
}

func (r *lbTestRun) RunCleanup() {
	if !FlagCleanup {
		return
	}

	cleanupCtx, cancelCleanupCtx := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancelCleanupCtx()

	for _, f := range slices.Backward(r.cleanupCb) {
		if err := f(cleanupCtx); err != nil {
			fmt.Printf("cleanup failed %s\n", err)
		}
	}

	r.cleanupCb = []func(ctx context.Context) error{}
}

func (r *lbTestRun) testsToExecute(ctx context.Context) ([]*LbTestFunc, error) {
	runRegexp, skipRegexp, err := runAndSkipRegexps()
	if err != nil {
		return nil, err
	}

	testsToExecute := []*LbTestFunc{}
	for _, test := range Tests {
		tf := NewLBTestFunc(r, ctx, test)

		skip := false
		for _, rgx := range skipRegexp {
			if rgx.MatchString(tf.Name()) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if len(runRegexp) == 0 {
			testsToExecute = append(testsToExecute, tf)
			continue
		}

		for _, rgx := range runRegexp {
			if rgx.MatchString(tf.Name()) {
				testsToExecute = append(testsToExecute, tf)
				break
			}
		}
	}

	if FlagShard.TotalShards > 0 {
		testsToExecute = shardLBTests(testsToExecute, FlagShard)
	}

	return testsToExecute, nil
}

func runAndSkipRegexps() ([]*regexp.Regexp, []*regexp.Regexp, error) {
	runRegexp := []*regexp.Regexp{}
	skipRegexp := []*regexp.Regexp{}
	for _, r := range FlagRun {
		rgx, err := regexp.Compile(strings.TrimPrefix(r, "!"))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse run-tests regexp (%s): %w", r, err)
		}
		if strings.HasPrefix(r, "!") {
			skipRegexp = append(skipRegexp, rgx)
			continue
		}
		runRegexp = append(runRegexp, rgx)
	}
	return runRegexp, skipRegexp, nil
}
