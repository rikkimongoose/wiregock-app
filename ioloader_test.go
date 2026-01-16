package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMockLoader_Reset(t *testing.T) {
	// Инициализация MockLoader с какими-то начальными данными
	loader := &MockLoader{
		data: map[string]string{
			"oldKey": "oldValue",
		},
	}

	// Данные, которые хотим загрузить через Reset
	newData := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	loader.Reset(newData)

	// Проверяем, что старые данные удалились
	require.NotContains(t, loader.data, "oldKey", "Старые данные должны быть очищены")

	// Проверяем, что новые данные добавились корректно
	require.Equal(t, "value1", loader.data["key1"])
	require.Equal(t, "value2", loader.data["key2"])

	// Проверка полного соответствия map
	require.Equal(t, newData, loader.data, "Данные после Reset должны совпадать с переданными")
}
