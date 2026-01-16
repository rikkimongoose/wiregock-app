package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadFileLinksList(t *testing.T) {
	data := `{
		"info": {{{ "foo.json" }}}
	}`
	templatePath := "foo.json"

	matches := LoadFileLinksList(data)
	require.Contains(t, matches, templatePath, "Template %s not found in data: %s", templatePath, data)
}

func TestUpdateFileLinks(t *testing.T) {
	source := `{
		"info": {{{ "foo.json" }}} ,
		"more{{{ "boo.json" }}}": null
	}`

	data := map[string]string{
		"foo.json": `{ "foo": "boo" }`,
	}
	expected := `{
		"info": { "foo": "boo" },
		"more": null
	}`

	result := UpdateFileLinks(source, data)
	require.JSONEq(t, expected, result, "Updated template does not match expected result")
}
