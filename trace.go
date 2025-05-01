package main

import (
	"fmt"
	"math/rand"
	"regexp"
	"time"
)

const charset = "abcdef0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
var zeroRegex = regexp.MustCompile(`^0+$`)

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	var result string
	for {
		for i := range b {
			b[i] = charset[seededRand.Intn(len(charset))]
		}
		result = string(b)
		if !zeroRegex.MatchString(result) {
			break
		}
	}
	return result
}

func GenerateTraceparent() string {
	block1 := StringWithCharset(32, charset)
	block2 := StringWithCharset(16, charset)
	return fmt.Sprintf("00-%s-%s-01", block1, block2)
}
