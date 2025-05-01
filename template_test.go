package main

import (
	"slices"
	"strings"
	"testing"
)

func TestLoadFileLinksList(t *testing.T) {
	data, templatePath := `{
		"info": {{{ "foo.json" }}}
	}`, "foo.json"

	matches := LoadFileLinksList(data)
	if !slices.Contains(matches, templatePath) {
		t.Fatalf("Not matched template %s in data: %s", templatePath, data)
	}
}

func TestUpdateFileLinks(t *testing.T) {
	source := `{
		"info": {{{ "foo.json" }}},
		"more{{{ "boo.json" }}}": null
	}`

	data := map[string]string{"foo.json": `{ "foo": "boo" }`}
	resultExpected := `{
		"info": { "foo": "boo" },
		"more": null
	}`

	resultReceived := UpdateFileLinks(source, data)

	if strings.Compare(resultExpected, resultReceived) != 0 {
		t.Fatalf("Not matched template %s in data: %s", source, data)
	}
}
