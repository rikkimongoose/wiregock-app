package main

import (
	b64 "encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/google/uuid"
)

type RequestData map[string]interface{}

var regExInnerFile = regexp.MustCompile(`\{\{\{\s*"(.*?)"\s*\}\}\}`)

func ParseQuery(values url.Values) map[string]map[string]string {
	response := map[string]map[string]string{}
	for key, value := range values {
		dataMap := map[string]string{}
		for index, valueItem := range value {
			dataMap[fmt.Sprintf("[%d]", index)] = valueItem
		}
		response[key] = dataMap
	}
	return response
}

func ToSingleValueMap(values map[string][]string) map[string]string {
	resp := map[string]string{}
	for key, value := range values {
		resp[key] = value[0]
	}
	return resp
}

func CookiesToMap(cookies []*http.Cookie) map[string]string {
	resp := map[string]string{}
	for _, cookie := range cookies {
		resp[cookie.Name] = cookie.Value
	}
	return resp
}

func LoadRequestData(req *http.Request) (*RequestData, error) {
	body, bodyBase64 := "", ""
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(b[:])
		bodyBase64 = b64.URLEncoding.EncodeToString(b)
	}
	return &RequestData{
		"request": RequestData{
			"id":           uuid.New().String(),
			"url":          req.URL.RequestURI(),
			"queryFull":    req.URL.Query(),
			"query":        ToSingleValueMap(req.URL.Query()),
			"method":       req.Method,
			"host":         req.Host,
			"port":         req.URL.Port(),
			"scheme":       req.URL.Scheme,
			"baseUrl":      req.URL.Host,
			"headersFull":  req.Header,
			"headers":      ToSingleValueMap(req.Header),
			"cookies":      CookiesToMap(req.Cookies()),
			"body":         body,
			"bodyAsBase64": bodyBase64,
		},
	}, nil
}

func LoadFileLinksList(source string) []string {
	// Ищем все вхождения
	matches := regExInnerFile.FindAllStringSubmatch(source, -1)
	if matches == nil {
		return nil // Нет совпадений
	}
	// Извлекаем первую группу (элемент $1) из каждого совпадения
	var result []string
	for _, match := range matches {
		if len(match) > 1 { // Проверяем, что есть хотя бы одна группа
			result = append(result, match[1])
		}
	}
	return result
}

func UpdateFileLinks(source string, data map[string]string) string {
	// Ищем все вхождения
	matches := regExInnerFile.FindAllStringSubmatch(source, -1)
	if matches == nil {
		return source
	}
	for _, match := range matches {
		if len(match) < 1 { // Проверяем, что есть хотя бы одна группа
			continue
		}
		fileName := match[1]
		regExInnerSource, err := regexp.Compile(fmt.Sprintf(`\{\{\{\s*"%s"\s*\}\}\}`, fileName))
		if err != nil {
			continue
		}
		val, ok := data[fileName]
		if !ok { // Если ключ есть, но значения нет
			source = regExInnerSource.ReplaceAllString(source, val)
			continue
		}
		source = regExInnerSource.ReplaceAllString(source, val)
	}
	return source
}
