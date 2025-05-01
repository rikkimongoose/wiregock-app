package main

import (
	"slices"
	"testing"
)

func TestLoadMethodsCheck(t *testing.T) {
	methods := LoadMethods("ANY")
	for _, method := range anyMethods {
		if !slices.Contains(methods, method) {
			t.Fatalf(`%s method isn't loaded from ANY`, method)
		}
	}
	methodsGetPost := LoadMethods("GET, POST")
	if !slices.Contains(methodsGetPost, "GET") {
		t.Fatalf(`%s method isn't loaded from "GET, POST"`, "GET")
	}
	if !slices.Contains(methodsGetPost, "POST") {
		t.Fatalf(`%s method isn't loaded by ANY`, "POST")
	}
}
