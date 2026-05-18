package ilb

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_testsToExecute(t *testing.T) {
	originalTests := Tests
	t.Cleanup(func() {
		Tests = originalTests
		FlagRun = nil
		FlagShard = TestShard{}
	})

	// Override global var for testing
	Tests = []func(t T){
		TestRequestedVIP,
		TestSharedVIP,
		TestBGPHealthCheck,
		TestBGPHealthCheckSubset,
		TestT2HealthCheckHTTP,
		TestHTTP2,
		TestHTTPPath,
		TestHTTPRoutes,
	}

	testCases := []struct {
		name          string
		flagRun       []string
		flagShard     TestShard
		expectedTests []string
	}{
		{
			name:    "all tests",
			flagRun: []string{},
			expectedTests: []string{
				"TestRequestedVIP",
				"TestSharedVIP",
				"TestBGPHealthCheck",
				"TestBGPHealthCheckSubset",
				"TestT2HealthCheckHTTP",
				"TestHTTP2",
				"TestHTTPPath",
				"TestHTTPRoutes",
			},
		},
		{
			name: "run and skip regexps",
			flagRun: []string{
				"TestRequestedVIP",
				"!TestSharedVIP",
				"!^TestBGPHealthCheck",
				"!^TestBGPHealthCheckSubset$",
				"^TestHTTP",
			},
			expectedTests: []string{
				"TestRequestedVIP",
				"TestHTTP2",
				"TestHTTPPath",
				"TestHTTPRoutes",
			},
		},
		{
			name:      "first shard",
			flagRun:   []string{},
			flagShard: TestShard{CurrentShard: 1, TotalShards: 3},
			expectedTests: []string{
				"TestRequestedVIP",
				"TestSharedVIP",
			},
		},
		{
			name:      "last shard after regex filtering",
			flagRun:   []string{"^TestHTTP|^TestBGP"},
			flagShard: TestShard{CurrentShard: 2, TotalShards: 2},
			expectedTests: []string{
				"TestHTTP2",
				"TestHTTPPath",
				"TestHTTPRoutes",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			FlagRun = tt.flagRun
			FlagShard = tt.flagShard

			actualTests, err := NewLBTestRun(t.Context(), "cilium").testsToExecute(t.Context())

			require.NoError(t, err)
			require.Len(t, actualTests, len(tt.expectedTests))
			for i := range actualTests {
				require.Equal(t, tt.expectedTests[i], actualTests[i].Name())
			}
		})
	}
}

func Test_runAndSkipRegexps(t *testing.T) {
	testCases := []struct {
		flagRun      []string
		runExpected  []*regexp.Regexp
		skipExpected []*regexp.Regexp
	}{
		{
			flagRun:      []string{},
			runExpected:  []*regexp.Regexp{},
			skipExpected: []*regexp.Regexp{},
		},
		{
			flagRun: []string{"!SkipTest1", "RunTest2", "!^SkipTest3$", "^RunTest4$"},
			runExpected: []*regexp.Regexp{
				regexp.MustCompile("RunTest2"),
				regexp.MustCompile("^RunTest4$"),
			},
			skipExpected: []*regexp.Regexp{
				regexp.MustCompile("SkipTest1"),
				regexp.MustCompile("^SkipTest3$"),
			},
		},
	}

	for _, tt := range testCases {
		FlagRun = tt.flagRun
		// function to test
		runActual, skipActual, err := runAndSkipRegexps()

		require.NoError(t, err)
		require.Equal(t, tt.runExpected, runActual)
		require.Equal(t, tt.skipExpected, skipActual)
	}
}

func TestTestShardSet(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedShard TestShard
		expectedError string
	}{
		{
			name:          "valid shard",
			input:         "3-of-4",
			expectedShard: TestShard{CurrentShard: 3, TotalShards: 4},
		},
		{
			name:          "invalid format",
			input:         "3/4",
			expectedError: "invalid shard format",
		},
		{
			name:          "current shard out of range",
			input:         "5-of-4",
			expectedError: "invalid shard value",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			var shard TestShard
			err := shard.Set(tt.input)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedShard, shard)
			require.Equal(t, tt.input, shard.String())
		})
	}
}

func Test_testsToExecute_AllShardsCoverFilteredTests(t *testing.T) {
	originalTests := Tests
	t.Cleanup(func() {
		Tests = originalTests
		FlagRun = nil
		FlagShard = TestShard{}
	})

	Tests = []func(t T){
		TestRequestedVIP,
		TestSharedVIP,
		TestBGPHealthCheck,
		TestBGPHealthCheckSubset,
		TestT2HealthCheckHTTP,
		TestHTTP2,
		TestHTTPPath,
		TestHTTPRoutes,
	}

	FlagRun = []string{"^TestHTTP|^TestBGP"}

	expectedTests, err := NewLBTestRun(t.Context(), "cilium").testsToExecute(t.Context())
	require.NoError(t, err)

	FlagShard = TestShard{}

	var actualTests []string
	for shard := 1; shard <= 3; shard++ {
		FlagShard = TestShard{CurrentShard: shard, TotalShards: 3}

		shardTests, err := NewLBTestRun(t.Context(), "cilium").testsToExecute(t.Context())
		require.NoError(t, err)

		for _, test := range shardTests {
			actualTests = append(actualTests, test.Name())
		}
	}

	require.Len(t, actualTests, len(expectedTests))
	for i, test := range expectedTests {
		require.Equal(t, test.Name(), actualTests[i])
	}
}

func Test_shardLBTests_EvenAndOdd(t *testing.T) {
	makeTests := func(n int) []*LbTestFunc {
		out := make([]*LbTestFunc, n)
		for i := range out {
			out[i] = &LbTestFunc{name: fmt.Sprintf("Test%d", i)}
		}
		return out
	}

	for _, totalTests := range []int{4, 5, 7, 10, 11} {
		tests := makeTests(totalTests)
		for _, totalShards := range []int{2, 3} {
			var collected []string
			for shard := 1; shard <= totalShards; shard++ {
				result := shardLBTests(tests, TestShard{CurrentShard: shard, TotalShards: totalShards})
				for _, tf := range result {
					collected = append(collected, tf.name)
				}
			}
			require.Len(t, collected, totalTests, "totalTests=%d totalShards=%d", totalTests, totalShards)
			for i, name := range collected {
				require.Equal(t, fmt.Sprintf("Test%d", i), name, "totalTests=%d totalShards=%d idx=%d", totalTests, totalShards, i)
			}
		}
	}
}
