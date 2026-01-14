package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMockLoader_Reset(t *testing.T) {
	// Создаём мок
	ml := NewMockLoader()

	// Проверяем, что изначально он пустой
	require.Empty(t, ml.data)

	// 1. Первый сброс с набором данных
	data1 := map[string]string{
		"a": "1",
		"b": "2",
	}
	ml.Reset(data1)

	// Проверяем, что данные скопированы
	require.Equal(t, data1, ml.data)

	// 2. Второй сброс с другим набором данных
	data2 := map[string]string{
		"x": "10",
		"y": "20",
	}
	ml.Reset(data2)

	// Проверяем, что предыдущие данные удалены и новые добавлены
	require.Equal(t, data2, ml.data)
	require.NotContains(t, ml.data, "a")
	require.NotContains(t, ml.data, "b")

	// 3. Сброс с пустой map
	ml.Reset(map[string]string{})
	require.Empty(t, ml.data)
}
