package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

type DataLoader interface {
	read(file string) ([]byte, error)
	readString(file string) string
	readStrings(fileNames []string) map[string]string
}

type IOLoader struct {
	log *zap.Logger
}

func (ioLoader IOLoader) read(file string) ([]byte, error) {
	byteValue, err := os.ReadFile(file)
	if err != nil {
		ioLoader.log.Error(`Error reading text from file`, zap.Error(err), zap.String("file", file))
		return []byte{}, err
	}
	return byteValue, nil
}

func (ioLoader IOLoader) readString(file string) string {
	byteValue, err := ioLoader.read(file)
	if err != nil {
		return ""
	}
	return string(byteValue)
}

func (ioLoader IOLoader) readStrings(fileNames []string) map[string]string {
	return ioLoader.readStringsData(fileNames)
}

func (ioLoader IOLoader) readStringsData(fileNames []string) map[string]string {
	resultMap := make(map[string]string)
	for _, fileName := range fileNames {
		b, err := os.ReadFile(fileName)
		if err != nil {
			ioLoader.log.Warn("Unable to load data from file, mentioned in template", zap.Error(err), zap.String("templateFileName", fileName))
			continue
		}
		resultMap[fileName] = string(b)
	}
	return resultMap
}

type MockLoader struct {
	Data map[string]string
}

func (mockLoader MockLoader) read(file string) ([]byte, error) {
	if value, exists := mockLoader.Data[file]; exists {
		return []byte(value), nil
	}
	return []byte{}, nil
}

func (mockLoader MockLoader) readString(file string) string {
	if value, exists := mockLoader.Data[file]; exists {
		return value
	}
	return ""
}

func (mockLoader MockLoader) readStrings(fileNames []string) map[string]string {
	resultMap := make(map[string]string)
	for _, fileName := range fileNames {
		resultMap[fileName] = mockLoader.readString(fileName)
	}
	return resultMap
}

type FileMocksLoader struct {
	config     *FileSourceConfig
	dataLoader DataLoader
	log        *zap.Logger
}

func (loader *FileMocksLoader) loadFilesList() []string {
	filesSource := []string{}
	dir, mask := "./", "*.json"
	if loader.config != nil {
		if loader.config.Dir != nil {
			dir = *loader.config.Dir
		}
		if loader.config.Mask != nil {
			mask = *loader.config.Mask
		}
		if len(loader.config.Files) != 0 {
			filesSource = append(filesSource, loader.config.Files...)
		}
	}

	foundMockfiles, err := findInDir(dir, mask)

	if err != nil {
		loader.log.Error(`Unable to search files by mask.`,
			zap.Error(err),
			zap.String("dir", dir),
			zap.String("mask", mask),
		)
	} else {
		filesSource = append(filesSource, foundMockfiles...)
	}
	return filesSource
}

func (loader FileMocksLoader) Load() []MockRoute {
	var mockRoutes []MockRoute
	filesSource := loader.loadFilesList()
	for _, file := range filesSource {
		jsonValue, err := loader.dataLoader.read(file)
		if err != nil {
			loader.log.Error(`Error loading JSON from file`, zap.Error(err), zap.String("file", file))
			continue
		}
		var mocks []MockData
		err = json.Unmarshal(jsonValue, &mocks)
		if err != nil {
			loader.log.Warn(`Unable to parse JSON array from file. Attempt to read as single value`, zap.Error(err), zap.String("file", file))
			var mockSingle MockData
			err = json.Unmarshal(jsonValue, &mockSingle)
			if err != nil {
				loader.log.Error(`Error parsing JSON single mock from file.`, zap.Error(err), zap.String("file", file))
				continue
			}
			mocks = append(mocks, mockSingle)
		}
		mockRoutes = append(mockRoutes, MockRoute{mocks})
		for _, mock := range mocks {
			loader.log.Info(`Successfully load route from file`, zap.String("urlPath", *mock.Request.UrlPath), zap.String("file", file))
		}
	}
	return mockRoutes
}

func findInDir(root, pattern string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}
