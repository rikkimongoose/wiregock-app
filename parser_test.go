package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/antchfx/jsonquery"
	"github.com/antchfx/xmlquery"
)

func TestParseRule(t *testing.T) {
	Contains := "Contains"
	EqualTo := "EqualTo"
	CaseInsensitive := false
	BinaryEqualTo := "BinaryEqualTo"
	DoesNotContain := "DoesNotContain"
	Matches := ".*"
	DoesNotMatch := ".*"
	Absent := true
	Before := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	After := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	EqualToDateTime := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	ActualFormat := "ActualFormat"
	EqualToJson := "{ \"total_results\": 4 }"
	IgnoreArrayOrder := true
	IgnoreExtraElements := true
	MatchesJsonPath := "$.welcome.message[1]"
	EqualToXml := "<thing>Hello</thing>"
	MatchesXPath := "//todo-item"
	MatchesJsonSchema := `{
		"$id": "https://example.com/person.schema.json",
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title": "Person",
		"type": "object",
		"properties": {
			"firstName": {
			"type": "string",
			"description": "The person's first name."
			},
			"lastName": {
			"type": "string",
			"description": "The person's last name."
			},
			"age": {
			"description": "Age in years which must be equal to or greater than zero.",
			"type": "integer",
			"minimum": 0
			}
		}
	}`

	filter := Filter{
		Contains:            &Contains,
		EqualTo:             &EqualTo,
		CaseInsensitive:     &CaseInsensitive,
		BinaryEqualTo:       &BinaryEqualTo,
		DoesNotContain:      &DoesNotContain,
		Matches:             &Matches,
		DoesNotMatch:        &DoesNotMatch,
		Absent:              &Absent,
		Before:              &Before,
		After:               &After,
		EqualToDateTime:     &EqualToDateTime,
		ActualFormat:        &ActualFormat,
		EqualToJson:         &EqualToJson,
		IgnoreArrayOrder:    &IgnoreArrayOrder,
		IgnoreExtraElements: &IgnoreExtraElements,
		MatchesJsonPath:     &XPathFilter{Expression: MatchesJsonPath},
		MatchesJsonSchema:   &MatchesJsonSchema,
		EqualToXml:          &EqualToXml,
		MatchesXPath:        &XPathFilter{Expression: MatchesXPath},
	}

	rules, err := parseRule(&filter)
	if err != nil {
		t.Fatalf(`Error parsing rule: %s`, err)
	}

	equalToBaseRule := EqualToBaseRule{
		IgnoreArrayOrder:    true,
		IgnoreExtraElements: true,
	}
	equalToJsonNode, err := jsonquery.Parse(strings.NewReader(EqualToJson))
	if err != nil {
		t.Fatalf(`Wrong example of Json Query: %s`, err)
	}
	equalToXmlNode, err := xmlquery.Parse(strings.NewReader(EqualToXml))
	if err != nil {
		t.Fatalf(`Wrong example of Xml Query: %s`, err)
	}
	if err != nil {
		t.Fatalf(`Wrong example of Xml XPath: %s`, err)
	}
	emptyBlockRule := BlockRule{rulesOr: []Rule{}}
	rulesChecker := RulesChecker{rules, t}
	rulesToCheck := map[string]Rule{
		"ContainsRule":          ContainsRule{Contains, CaseInsensitive},
		"EqualToRule":           EqualToRule{EqualTo, CaseInsensitive},
		"EqualToBinaryRule":     EqualToBinaryRule{[]byte(BinaryEqualTo)},
		"NotRule.ContainsRule":  NotRule{ContainsRule{DoesNotContain, CaseInsensitive}},
		"RegExRule":             RegExRule{regexp.MustCompile(Matches)},
		"NotRule.RegExRule":     NotRule{RegExRule{regexp.MustCompile(Matches)}},
		"AbsentRule":            AbsentRule{},
		"DateTimeRule":          DateTimeRule{&Before, &After, &EqualToDateTime, ActualFormat},
		"EqualToJsonRule":       EqualToJsonRule{node: equalToJsonNode, EqualToBaseRule: equalToBaseRule},
		"EqualToXmlRule":        EqualToXmlRule{node: equalToXmlNode, EqualToBaseRule: equalToBaseRule},
		"EqualToJsonSchemaRule": MatchesJsonSchemaRule{MatchesJsonSchema},
		"MatchesJsonPathRule":   MatchesJsonPathRule{path: MatchesJsonPath, innerRule: emptyBlockRule},
	}
	for key, rule := range rulesToCheck {
		rulesChecker.checkRule(rule, key)
	}
}

type RulesChecker struct {
	rules []Rule
	t     *testing.T
}

func (rulesChecker RulesChecker) checkRule(ruleToCheck Rule, ruleTitle string) {
	for _, rule := range rulesChecker.rules {
		if reflect.DeepEqual(rule, ruleToCheck) {
			return
		}
	}
	rulesChecker.t.Fatalf(`Not parsed: %s`, ruleTitle)
}

func TestParseRules(t *testing.T) {
	Contains := "Contains"
	CaseInsensitive := false
	filter := Filter{
		Contains: &Contains,
		And:      []Filter{{Contains: &Contains}},
		Or:       []Filter{{Contains: &Contains}},
	}

	rules, err := parseRules(&filter, true)
	rulesAnd := rules.rulesAnd
	rulesOr := rules.rulesOr
	rule := ContainsRule{Contains, CaseInsensitive}
	if err != nil {
		t.Fatalf(`Error parsing rules: %s`, err)
	}
	if !reflect.DeepEqual(rulesAnd[0], rule) {
		t.Fatalf(`Error parsing rule And: %s`, rulesAnd[0])
	}
	if !reflect.DeepEqual(rulesAnd[1], rule) {
		t.Fatalf(`Error parsing rule And: %s`, rulesAnd[1])
	}
	if !reflect.DeepEqual(rulesOr[0], rule) {
		t.Fatalf(`Error parsing rule Or: %s`, rulesOr[0])
	}
}
