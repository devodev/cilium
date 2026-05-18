package ilb

import (
	"fmt"
	"strconv"
	"strings"
)

const shardSeparator = "-of-"

type TestShard struct {
	TotalShards  int
	CurrentShard int
}

func (s *TestShard) String() string {
	if s == nil || s.TotalShards == 0 {
		return ""
	}

	return fmt.Sprintf("%d%s%d", s.CurrentShard, shardSeparator, s.TotalShards)
}

func (s *TestShard) Set(value string) error {
	currentShard, totalShards, ok := strings.Cut(value, shardSeparator)
	if !ok {
		return fmt.Errorf("invalid shard format %q, expected CURRENT-of-TOTAL", value)
	}

	current, err := strconv.Atoi(currentShard)
	if err != nil {
		return fmt.Errorf("invalid current shard %q: %w", currentShard, err)
	}

	total, err := strconv.Atoi(totalShards)
	if err != nil {
		return fmt.Errorf("invalid total shards %q: %w", totalShards, err)
	}

	if total <= 0 || current <= 0 || current > total {
		return fmt.Errorf("invalid shard value %q, expected 1 <= CURRENT <= TOTAL", value)
	}

	s.CurrentShard = current
	s.TotalShards = total
	return nil
}

func (s *TestShard) Type() string {
	return "CURRENT-of-TOTAL"
}

func shardLBTests(tests []*LbTestFunc, shard TestShard) []*LbTestFunc {
	if shard.TotalShards == 0 || len(tests) == 0 {
		return tests
	}

	start := len(tests) * (shard.CurrentShard - 1) / shard.TotalShards
	end := len(tests) * shard.CurrentShard / shard.TotalShards
	return tests[start:end]
}
