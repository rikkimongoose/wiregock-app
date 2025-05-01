package main

import (
	"strings"
)

var anyMethods = [...]string{"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "POST", "PATCH", "CONNECT"}

func LoadMethods(methodNames string) []string {
	if strings.Compare(methodNames, "ANY") == 0 {
		return anyMethods[:]
	}
	splitRaw := strings.Split(methodNames, ",")
	splitResult := []string{}
	for _, splitted := range splitRaw {
		splitResult = append(splitResult, strings.ToUpper(strings.Trim(splitted, " ")))
	}
	return splitResult
}
