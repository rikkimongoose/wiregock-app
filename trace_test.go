package main

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateTraceparent calls GenerateTraceparent, checking
// for a valid return value.
func TestGenerateTraceparent(t *testing.T) {
	traceRegex := regexp.MustCompile(`^00-[a-f\d]{32}-[a-f\d]{16}-01$`)
	msg := GenerateTraceparent()
	require.Regexp(t, traceRegex, msg, "Generated traceparent ID is invalid: %s", msg)
}
