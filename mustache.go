package main

import (
	"net/http"

	"github.com/cbroglie/mustache"
	"go.uber.org/zap"
)

type MustacheService struct {
	dataLoader DataLoader
	log        *zap.Logger
}

func (service MustacheService) replace(w http.ResponseWriter, body string, context ...interface{}) string {
	result, err := mustache.Render(body, context)
	if err != nil {
		service.log.Error("Implementing template data to responseBody", zap.Error(err))
		if w != nil {
			http.Error(w, "Error implementing template data to responseBody", http.StatusInternalServerError)
		}
		return body
	}
	fileLinksList := LoadFileLinksList(result)
	if len(fileLinksList) > 0 {
		filesDataMap := service.dataLoader.readStrings(fileLinksList)
		if len(filesDataMap) > 0 {
			filesDataMap := service.updateDataInFiles(filesDataMap, context)
			result = UpdateFileLinks(body, filesDataMap)
		}
	}
	return result
}

func (service MustacheService) updateDataInFiles(dataMap map[string]string, context ...interface{}) map[string]string {
	resultMap := make(map[string]string)
	for fileName, fileSource := range dataMap {
		result, err := mustache.Render(fileSource, context)
		if err != nil {
			service.log.Warn("Wrong mustache template in file.", zap.Error(err), zap.String("templateFileName", fileName))
			resultMap[fileName] = fileSource
		}
		resultMap[fileName] = result
	}
	return resultMap
}
