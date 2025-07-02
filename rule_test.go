package main

import (
	"regexp"
	"testing"
	"time"
)

func TestEqualToRuleCheck(t *testing.T) {
	ruleCaseSensitive := EqualToRule{"test", false}
	res, err := ruleCaseSensitive.check("test")
	if err != nil || !res {
		t.Fatalf(`EqualToRule failed checking: test`)
	}
	ruleCaseInsensitive := EqualToRule{"test", true}
	res, err = ruleCaseInsensitive.check("tEst")
	if err != nil || !res {
		t.Fatalf(`EqualToRule failed checking: tEst`)
	}
}

func TestEqualToBinaryRuleCheck(t *testing.T) {
	rule := EqualToBinaryRule{[]byte("test")}
	res, err := rule.check("test")
	if err != nil || !res {
		t.Fatalf(`EqualToBinaryRule failed checking: test`)
	}
}

func TestNotRuleRuleCheck(t *testing.T) {
	ruleNotTrue := NotRule{TrueRule{}}
	res, err := ruleNotTrue.check("test")
	if err != nil || res {
		t.Fatalf(`NotRule(TrueRule) failed checking`)
	}
	ruleNotFalse := NotRule{FalseRule{}}
	res, err = ruleNotFalse.check("test")
	if err != nil || !res {
		t.Fatalf(`NotRule(FalseRule) failed checking`)
	}
}

func TestContainsRuleCheck(t *testing.T) {
	ruleCaseSensitive := ContainsRule{"test", false}
	res, err := ruleCaseSensitive.check("testing")
	if err != nil || !res {
		t.Fatalf(`ContainsRule failed checking: test`)
	}
	ruleCaseInsensitive := ContainsRule{"test", true}
	res, err = ruleCaseInsensitive.check("tEsting")
	if err != nil || !res {
		t.Fatalf(`ContainsRule failed checking: tEsting`)
	}
}

func TestDateTimeRuleCheck(t *testing.T) {
	sourceData := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	ruleEqualToDateTime := DateTimeRule{equalToDateTime: &sourceData, timeFormat: time.RFC3339}
	res, err := ruleEqualToDateTime.check("2009-11-10T23:00:00Z")
	if err != nil || !res {
		t.Fatalf(`Rule doesn't check that %s is equal %s Error: %s`, "2009-11-10T23:00:00Z", sourceData, err)
	}
	ruleBefore := DateTimeRule{before: &sourceData, timeFormat: time.RFC3339}
	res, err = ruleBefore.check("2009-11-09T23:00:00Z")
	if err != nil || !res {
		t.Fatalf(`Rule doesn't check that %s is before %s. Error: %s`, "2009-11-09T23:00:00Z", sourceData, err)
	}
	ruleAfter := DateTimeRule{after: &sourceData, timeFormat: time.RFC3339}
	res, err = ruleAfter.check("2009-11-11T23:00:00Z")
	if err != nil || !res {
		t.Fatalf(`Rule doesn't check that %s is after %s. Error: %s`, "2009-11-11T23:00:00Z", sourceData, err)
	}
}

func TestMatchesJsonPathRule(t *testing.T) {
	ruleSchema := "$.welcome.message[1]"
	ruleMatchesJsonPath := MatchesJsonPathRule{ruleSchema, nil}
	data := `{
		"welcome":{
				"message":["Good Morning", "Hello World!"]
			}
		}`
	res, err := ruleMatchesJsonPath.check(data)
	if err != nil || !res {
		t.Fatalf(`MatchesJsonPathRule failed checking by rule %s: %s. Error: %s"`, ruleSchema, data, err)
	}
}

func TestMatchesJsonSchemaRule(t *testing.T) {
	ruleSchema := `{
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
	ruleMatchesJsonSchemaRule := MatchesJsonSchemaRule{ruleSchema}
	data := `{
		"firstName": "John",
		"lastName": "Doe",
		"age": 21
	}`
	res, err := ruleMatchesJsonSchemaRule.check(data)
	if err != nil || !res {
		t.Fatalf(`MatchesJsonSchemaRule failed checking by rule %s: %s. Error: %s`, ruleSchema, data, err)
	}
}

func TestAbsentRuleCheck(t *testing.T) {
	absentRule := AbsentRule{}
	res, err := absentRule.check("test")
	if err != nil && res {
		t.Fatalf(`Absent rule catches existing. Error: %s`, err)
	}
	res, err = absentRule.check("")
	if err != nil && !res {
		t.Fatalf(`Absent rule doesn't catch non-existing. Error: %s`, err)
	}
}

func TestWildcardsRuleCheck(t *testing.T) {
	checkWildcard("test", "test", false, t)
	checkWildcard("?a*da*d.?*", "daaadabadmanda", false, t)
	checkWildcard("?a*da*d.?*", "DaaadAbadmanda", true, t)
}

func checkWildcard(wildcard string, value string, caseInsensitive bool, t *testing.T) {
	ruleWildcards := WildcardsRule{wildcard, caseInsensitive}
	res, err := ruleWildcards.check(value)
	if err != nil || !res {
		t.Fatalf(`WildcardsRule %s failed checking: %s`, wildcard, value)
	}
}

func TestRegExRuleCheck(t *testing.T) {
	regEx := `00-[a-f\d]{32}-[a-f\d]{16}-01`
	value := "/00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01/"
	ruleRegEx := RegExRule{regexp.MustCompile(regEx)}
	res, err := ruleRegEx.check(value)
	if err != nil || !res {
		t.Fatalf(`RegExRule %s failed checking: %s`, regEx, value)
	}
}

func TestMatchesJsonXPathRule(t *testing.T) {
	xPathFilterProps := XPathFilterProps{true, true, true}
	xPathJsonFactory := XPathJsonFactory{}
	exp := "$.foo"
	json := `{ "boo": 42 }`
	xPathFilter := XPathFilter{
		EqualToJson: &json,
		Expression:  exp,
	}
	rule, err := xPathJsonFactory.generateMatchesXPathRule(&xPathFilter, &xPathFilterProps)
	if err != nil {
		t.Fatalf(`MatchesJsonXPathRule %s failed with error: %s`, json, err)
	}
	value := `{ "foo": { "boo": 42 } }`
	res, err := rule.check(value)
	if err != nil || !res {
		t.Fatalf(`MatchesJsonXPathRule %s failed checking: %s`, json, value)
	}
}

func TestMatchesJsonXPathRuleArray(t *testing.T) {
	xPathFilterProps := XPathFilterProps{true, true, true}
	xPathJsonFactory := XPathJsonFactory{}
	exp := "$.foo"
	json := `{ "boo": 42 }`
	xPathFilter := XPathFilter{
		EqualToJson: &json,
		Expression:  exp,
	}
	rule, err := xPathJsonFactory.generateMatchesXPathRule(&xPathFilter, &xPathFilterProps)
	if err != nil {
		t.Fatalf(`MatchesJsonXPathRule %s failed with error: %s`, json, err)
	}
	value := `{ "foo": [{ "boo": 42 }, { "goo": 42 }] }`
	res, err := rule.check(value)
	if err != nil || !res {
		t.Fatalf(`MatchesJsonXPathRule %s failed checking: %s`, json, value)
	}
}

func TestMatchesXmlXPathRule(t *testing.T) {
	xPathFilterProps := XPathFilterProps{true, true, true}
	xPathXmlFactory := XPathXmlFactory{}
	exp := "//todo-item"
	xml := "<todo-item>Do the washing</todo-item>"
	xPathFilter := XPathFilter{
		EqualToXml: &xml,
		Expression: exp,
	}
	rule, err := xPathXmlFactory.generateMatchesXPathRule(&xPathFilter, &xPathFilterProps)
	if err != nil {
		t.Fatalf(`MatchesXmlXPathRule %s failed with error: %s`, xml, err)
	}
	value := "<foo><todo-item>Do the washing</todo-item></foo>"
	res, err := rule.check(value)
	if err != nil || !res {
		t.Fatalf(`MatchesXmlXPathRule %s failed checking: %s`, xml, value)
	}
}

func TestEqualToJsonRule(t *testing.T) {
	xPathFilterProps := XPathFilterProps{true, true, true}
	xPathJsonFactory := XPathJsonFactory{}
	json := `{"foo": "boo", "boo": "foo"}`
	rule, err := xPathJsonFactory.generateEqualsRule(json, &xPathFilterProps)
	if err != nil {
		t.Fatalf(`EqualToJsonRule %s failed with error: %s`, json, err)
	}
	value := `{"boo": "foo", "foo": "boo"}`
	res, err := rule.check(value)
	if err != nil || !res {
		t.Fatalf(`EqualToJsonRule %s failed checking: %s`, json, value)
	}
}

func TestEqualToXmlRule(t *testing.T) {
	xPathFilterProps := XPathFilterProps{true, true, true}
	xPathXmlFactory := XPathXmlFactory{}
	xml := "<thing>Hello</thing>"
	rule, err := xPathXmlFactory.generateEqualsRule(xml, &xPathFilterProps)
	if err != nil {
		t.Fatalf(`EqualToXmlRule %s failed with error: %s`, xml, err)
	}
	value := "<thing>Hello</thing>"
	res, err := rule.check(value)
	if err != nil || !res {
		t.Fatalf(`EqualToXmlRule %s failed checking: %s`, xml, value)
	}
}

func TestBlockRule(t *testing.T) {
	ruleAndTrueFalse := BlockRule{
		rulesAnd: []Rule{TrueRule{}, FalseRule{}},
	}
	ok, _ := ruleAndTrueFalse.check("")
	if ok {
		t.Fatalf(`ruleAndTrueFalse failed checking`)
	}
	ruleAndTrueTrue := BlockRule{
		rulesAnd: []Rule{TrueRule{}, TrueRule{}},
	}
	ok, _ = ruleAndTrueTrue.check("")
	if !ok {
		t.Fatalf(`ruleAndTrueTrue failed checking`)
	}
	ruleOrTrueFalse := BlockRule{
		rulesOr: []Rule{TrueRule{}, FalseRule{}},
	}
	ok, _ = ruleOrTrueFalse.check("")
	if !ok {
		t.Fatalf(`ruleOrTrueFalse failed checking`)
	}
	ruleOrFalseFalse := BlockRule{
		rulesOr: []Rule{FalseRule{}, FalseRule{}},
	}
	ok, _ = ruleOrFalseFalse.check("")
	if ok {
		t.Fatalf(`ruleOrFalseFalse failed checking`)
	}
	ruleEmpty := BlockRule{}
	ok, _ = ruleEmpty.check("")
	if !ok {
		t.Fatalf(`ruleEmpty failed checking`)
	}
}

//TODO - UnitTests for MatchesJsonXPathRule, MatchesXmlXPathRule, EqualToJsonRule, EqualToXmlRule
