package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/PaesslerAG/jsonpath"
	"github.com/antchfx/jsonquery"
	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"github.com/xeipuuv/gojsonschema"
)

type Rule interface {
	check(str string) (bool, error)
}

type NotRule struct {
	base Rule
}

type EqualToRule struct {
	val             string
	caseInsensitive bool
}

type EqualToBinaryRule struct {
	val []byte
}

type DateTimeRule struct {
	before          *time.Time
	after           *time.Time
	equalToDateTime *time.Time
	timeFormat      string //default: time.RFC3339
}

type ContainsRule struct {
	val             string
	caseInsensitive bool
}

type WildcardsRule struct {
	val             string
	caseInsensitive bool
}
type RegExRule struct {
	regex *regexp.Regexp
}

type MatchesXmlXPathRule struct {
	xPath     *xpath.Expr
	innerRule Rule
}

type MatchesJsonPathRule struct {
	path      string
	innerRule Rule
}

type MatchesJsonSchemaRule struct {
	schema string
}

type EqualToBaseRule struct {
	IgnoreArrayOrder    bool
	IgnoreExtraElements bool
}

type EqualToXmlRule struct {
	node *xmlquery.Node
	EqualToBaseRule
}

type EqualToJsonRule struct {
	node *jsonquery.Node
	EqualToBaseRule
}

type AbsentRule struct {
}

type TrueRule struct {
}

type FalseRule struct {
}

type BlockRule struct {
	rulesAnd []Rule
	rulesOr  []Rule
}

func (rule NotRule) check(str string) (bool, error) {
	res, err := rule.base.check(str)
	return !res, err
}

func (rule EqualToRule) check(str string) (bool, error) {
	if rule.caseInsensitive {
		return strings.EqualFold(rule.val, str), nil
	}
	return strings.Compare(rule.val, str) == 0, nil
}

func (rule EqualToBinaryRule) check(str string) (bool, error) {
	return bytes.Equal(rule.val, []byte(str)), nil
}

func (rule DateTimeRule) check(str string) (bool, error) {
	sourceTime, error := time.Parse(rule.timeFormat, str)
	if error != nil {
		return false, error
	}
	if rule.equalToDateTime != nil && !sourceTime.Equal(*rule.equalToDateTime) {
		return false, nil
	}
	if rule.before != nil && !sourceTime.Before(*rule.before) {
		return false, nil
	}
	if rule.after != nil && !sourceTime.After(*rule.after) {
		return false, nil
	}
	return true, nil
}

func (rule ContainsRule) check(str string) (bool, error) {
	if rule.caseInsensitive {
		return strings.Contains(strings.ToLower(str), strings.ToLower(rule.val)), nil
	}
	return strings.Contains(str, rule.val), nil
}

func (rule WildcardsRule) check(str string) (bool, error) {
	if rule.caseInsensitive {
		return wildcard.Match(strings.ToLower(rule.val), strings.ToLower(str)), nil
	}
	return wildcard.Match(rule.val, str), nil
}

func (rule RegExRule) check(str string) (bool, error) {
	return rule.regex.MatchString(str), nil
}

func (rule EqualToXmlRule) check(str string) (bool, error) {
	node, err := xmlquery.Parse(strings.NewReader(str))
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(*rule.node, *node), nil
}

func (rule EqualToJsonRule) check(str string) (bool, error) {
	node, err := jsonquery.Parse(strings.NewReader(str))
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(*rule.node, *node), nil
}

func (rule MatchesXmlXPathRule) check(str string) (bool, error) {
	nodeBase, err := xmlquery.Parse(strings.NewReader(str))
	if err != nil {
		return false, err
	}
	if rule.innerRule != nil {
		nodesByXPath := xmlquery.QuerySelectorAll(nodeBase, rule.xPath)
		for _, node := range nodesByXPath {
			ok, err := rule.innerRule.check(node.OutputXML(true))
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	return (xmlquery.QuerySelector(nodeBase, rule.xPath) != nil), nil
}

func (rule MatchesJsonPathRule) check(str string) (bool, error) {
	v := interface{}(nil)
	json.Unmarshal([]byte(str), &v)
	result, err := jsonpath.Get(rule.path, v)
	if err != nil {
		return false, err
	}
	if rule.innerRule != nil {
		results, err := ToArrayGeneric[any](result)
		if err != nil {
			return false, err
		}
		if len(results) == 0 {
			return false, nil
		}
		for _, resultItem := range results {
			jsonData, err := json.Marshal(resultItem)
			if err != nil {
				return false, err
			}
			ok, err := rule.innerRule.check(string(jsonData))
			if err != nil {
				return false, err
			}
			if ok {
				return ok, err
			}
		}
	}
	return result != nil, nil
}

// ToArray преобразует входные данные в массив
func ToArrayGeneric[T any](input any) ([]T, error) {
	val := reflect.ValueOf(input)
	var result []T

	switch val.Kind() {
	case reflect.Slice, reflect.Array:
		result = make([]T, val.Len())
		for i := 0; i < val.Len(); i++ {
			result[i] = val.Index(i).Interface().(T)
		}
	default:
		result = []T{input.(T)}
	}

	return result, nil
}

func (rule MatchesJsonSchemaRule) check(str string) (bool, error) {
	schemaLoader := gojsonschema.NewStringLoader(rule.schema)
	documentLoader := gojsonschema.NewStringLoader(str)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return false, err
	}
	if result.Valid() {
		return true, nil
	}
	var errs []error
	for _, desc := range result.Errors() {
		errs = append(errs, errors.New(desc.Description()))
	}
	return false, errors.Join(errs...)
}

func (rule AbsentRule) check(str string) (bool, error) {
	return len(str) == 0, nil
}

func (rule TrueRule) check(str string) (bool, error) {
	return true, nil
}

func (rule FalseRule) check(str string) (bool, error) {
	return false, nil
}

func (rule BlockRule) check(str string) (bool, error) {
	if rule.rulesAnd != nil {
		for _, ruleAnd := range rule.rulesAnd {
			res, err := ruleAnd.check(str)
			if err != nil {
				return false, err
			}
			if !res {
				return false, nil
			}
		}
	}
	resultAnd := rule.rulesAnd == nil || len(rule.rulesAnd) > 0
	if rule.rulesOr != nil {
		for _, ruleOr := range rule.rulesOr {
			res, err := ruleOr.check(str)
			if err != nil {
				return false, err
			}
			if res {
				return true, nil
			}
		}
	}
	resultOr := (rule.rulesOr == nil) || len(rule.rulesOr) == 0
	return resultAnd && resultOr, nil
}

func generateXPath(str string, namespaces map[string]string) (*xpath.Expr, error) {
	if namespaces != nil {
		return xpath.CompileWithNS(str, namespaces)
	}
	return xpath.Compile(str)
}
