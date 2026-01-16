package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadMethodsCheck(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "ANY loads all methods",
			input: "ANY",
			want:  anyMethods[:],
		},
		{
			name:  "GET, POST",
			input: "GET, POST",
			want:  []string{"GET", "POST"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			methods := LoadMethods(tt.input)

			for _, m := range tt.want {
				require.Contains(t, methods, m)
			}
		})
	}
}
