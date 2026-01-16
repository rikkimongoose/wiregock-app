package main

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEqualToRuleCheck(t *testing.T) {
	tests := []struct {
		name  string
		rule  EqualToRule
		input string
		want  bool
	}{
		{
			name:  "case sensitive",
			rule:  EqualToRule{"test", false},
			input: "test",
			want:  true,
		},
		{
			name:  "case insensitive",
			rule:  EqualToRule{"test", true},
			input: "tEst",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRuleCheck(t, &tt.rule, tt.input, tt.want)
		})
	}
}

func TestEqualToBinaryRuleCheck(t *testing.T) {
	rule := &EqualToBinaryRule{[]byte("test")}
	requireRuleCheck(t, rule, "test", true)
}

func TestNotRuleCheck(t *testing.T) {
	tests := []struct {
		name  string
		rule  Rule
		input string
		want  bool
	}{
		{
			name:  "not true",
			rule:  &NotRule{&TrueRule{}},
			input: "test",
			want:  false,
		},
		{
			name:  "not false",
			rule:  &NotRule{&FalseRule{}},
			input: "test",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRuleCheck(t, tt.rule, tt.input, tt.want)
		})
	}
}

func TestContainsRuleCheck(t *testing.T) {
	for _, rule := range []ContainsRule{
		{"test", false},
		{"test", true},
	} {
		requireRuleCheck(t, &rule, "testing", true)
	}
}

func TestDateTimeRuleCheck(t *testing.T) {
	source := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		rule  *DateTimeRule
		input string
		want  bool
	}{
		{
			name: "equal to datetime",
			rule: &DateTimeRule{
				equalToDateTime: &source,
				timeFormat:      time.RFC3339,
			},
			input: "2009-11-10T23:00:00Z",
			want:  true,
		},
		{
			name: "before datetime",
			rule: &DateTimeRule{
				before:     &source,
				timeFormat: time.RFC3339,
			},
			input: "2009-11-09T23:00:00Z",
			want:  true,
		},
		{
			name: "after datetime",
			rule: &DateTimeRule{
				after:      &source,
				timeFormat: time.RFC3339,
			},
			input: "2009-11-11T23:00:00Z",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRuleCheck(t, tt.rule, tt.input, true)
		})
	}
}

func TestMatchesJsonRules(t *testing.T) {
	tests := []struct {
		name  string
		rule  Rule
		input string
	}{
		{
			name: "json path",
			rule: &MatchesJsonPathRule{
				"$.welcome.message[1]",
				nil,
			},
			input: `{
				"welcome": {
					"message": ["Good Morning", "Hello World!"]
				}
			}`,
		},
		{
			name: "json schema",
			rule: &MatchesJsonSchemaRule{`{
				"type": "object",
				"properties": {
					"firstName": {"type": "string"},
					"lastName": {"type": "string"},
					"age": {"type": "integer", "minimum": 0}
				}
			}`},
			input: `{
				"firstName": "John",
				"lastName": "Doe",
				"age": 21
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRuleCheck(t, tt.rule, tt.input, true)
		})
	}
}

func TestAbsentRuleCheck(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"present", "test", false},
		{"absent", "", true},
	}

	rule := AbsentRule{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRuleCheck(t, &rule, tt.input, tt.want)
		})
	}
}

func TestWildcardsRuleCheck(t *testing.T) {
	tests := []struct {
		name            string
		wildcard        string
		value           string
		caseInsensitive bool
	}{
		{"exact", "test", "test", false},
		{"wildcard", "?a*da*d.?*", "daaadabadmanda", false},
		{"wildcard case-insensitive", "?a*da*d.?*", "DaaadAbadmanda", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := WildcardsRule{tt.wildcard, tt.caseInsensitive}
			requireRuleCheck(t, &rule, tt.value, true)
		})
	}
}

func TestRegExRuleCheck(t *testing.T) {
	rule := RegExRule{
		regexp.MustCompile(`00-[a-f\d]{32}-[a-f\d]{16}-01`),
	}
	value := "/00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01/"

	requireRuleCheck(t, &rule, value, true)
}

func TestMatchesXPathRules(t *testing.T) {
	props := XPathFilterProps{true, true, true}

	tests := []struct {
		name    string
		factory func() (Rule, error)
		input   string
	}{
		{
			name: "json xpath object",
			factory: func() (Rule, error) {
				json := `{ "boo": 42 }`
				filter := XPathFilter{
					EqualToJson: &json,
					Expression:  "$.foo",
				}
				xPathJsonFactory := XPathJsonFactory{}
				return xPathJsonFactory.GenerateMatchesXPathRule(&filter, &props)
			},
			input: `{ "foo": { "boo": 42 } }`,
		},
		{
			name: "xml xpath",
			factory: func() (Rule, error) {
				xml := "<todo-item>Do the washing</todo-item>"
				filter := XPathFilter{
					EqualToXml: &xml,
					Expression: "//todo-item",
				}
				xPathXmlFactory := XPathXmlFactory{}
				return xPathXmlFactory.GenerateMatchesXPathRule(&filter, &props)
			},
			input: "<foo><todo-item>Do the washing</todo-item></foo>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := tt.factory()
			require.NoError(t, err)
			requireRuleCheck(t, rule, tt.input, true)
		})
	}
}

func TestEqualToRules(t *testing.T) {
	props := XPathFilterProps{true, true, true}

	tests := []struct {
		name    string
		factory func() (Rule, error)
		input   string
	}{
		{
			name: "json equals",
			factory: func() (Rule, error) {
				json := `{"foo": "boo", "boo": "foo"}`
				xPathJsonFactory := XPathJsonFactory{}
				return xPathJsonFactory.GenerateEqualsRule(json, &props)
			},
			input: `{"boo": "foo", "foo": "boo"}`,
		},
		{
			name: "xml equals",
			factory: func() (Rule, error) {
				xml := "<thing>Hello</thing>"
				xPathXmlFactory := XPathXmlFactory{}
				return xPathXmlFactory.GenerateEqualsRule(xml, &props)
			},
			input: "<thing>Hello</thing>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := tt.factory()
			require.NoError(t, err)
			requireRuleCheck(t, rule, tt.input, true)
		})
	}
}

func TestBlockRule(t *testing.T) {
	tests := []struct {
		name string
		rule BlockRule
		want bool
	}{
		{
			name: "and true false",
			rule: BlockRule{rulesAnd: []Rule{&TrueRule{}, &FalseRule{}}},
			want: false,
		},
		{
			name: "and true true",
			rule: BlockRule{rulesAnd: []Rule{&TrueRule{}, &TrueRule{}}},
			want: true,
		},
		{
			name: "or true false",
			rule: BlockRule{rulesOr: []Rule{&TrueRule{}, &FalseRule{}}},
			want: true,
		},
		{
			name: "or false false",
			rule: BlockRule{rulesOr: []Rule{&FalseRule{}, &FalseRule{}}},
			want: false,
		},
		{
			name: "empty",
			rule: BlockRule{},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := tt.rule.check("")
			require.NoError(t, err)
			require.Equal(t, tt.want, ok)
		})
	}
}

func requireRuleCheck(t *testing.T, rule Rule, input string, want bool) {
	t.Helper()

	res, err := rule.check(input)
	require.NoError(t, err)
	require.Equal(t, want, res)
}
