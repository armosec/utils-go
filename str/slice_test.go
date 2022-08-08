package str

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringInSlice(t *testing.T) {
	assert.True(t, StringInSlice([]string{"a"}, "a"))
	assert.True(t, StringInSlice([]string{"a", "b", "c"}, "a"))
	assert.True(t, StringInSlice([]string{"a", "b", "c"}, "b"))
	assert.True(t, StringInSlice([]string{"a", "b", "c"}, "c"))
	assert.True(t, StringInSlice([]string{"a", "a"}, "a"))
	assert.False(t, StringInSlice([]string{"a", "b", "c"}, "d"))
	assert.False(t, StringInSlice([]string{""}, "a"))
	assert.False(t, StringInSlice([]string{"a"}, ""))
}

func TestStringInSliceCaseInsensitive(t *testing.T) {
	assert.True(t, StringInSliceCaseInsensitive([]string{"A"}, "a"))
	assert.True(t, StringInSliceCaseInsensitive([]string{"a"}, "A"))
	assert.True(t, StringInSlice([]string{"A", "a", "b", "c"}, "a"))
	assert.True(t, StringInSlice([]string{"a", "Bb", "cC"}, "cC"))
	assert.True(t, StringInSlice([]string{"a", "Bb", "Cc"}, "Cc"))
	assert.True(t, StringInSlice([]string{"a", "Bb", "C c"}, "C c"))
	assert.False(t, StringInSlice([]string{"a", "bb", "c"}, "b"))
}

func TestMapStringToSlice(t *testing.T) {
	assert.ElementsMatch(t, MapStringToSlice(map[string]interface{}{"a": nil}), []string{"a"})
	assert.ElementsMatch(t, MapStringToSlice(map[string]interface{}{"a": nil, "b": nil}), []string{"a", "b"})
	assert.ElementsMatch(t, MapStringToSlice(nil), []string{})
	assert.ElementsMatch(t, MapStringToSlice(map[string]interface{}{}), []string{})
}

func TestSliceStringToUnique(t *testing.T) {
	assert.ElementsMatch(t, SliceStringToUnique([]string{"a"}), []string{"a"})
	assert.ElementsMatch(t, SliceStringToUnique([]string{}), []string{})
	assert.ElementsMatch(t, SliceStringToUnique([]string{"a", "b", "b", "a"}), []string{"a", "b"})
}

func TestRemoveIndexFromStringList(t *testing.T) {
	type sliceTestSuite struct {
		origin   []string
		expected []string
		index    int
	}

	tests := map[string]sliceTestSuite{
		"remove first": {
			origin:   []string{"a", "b", "c"},
			expected: []string{"c", "b"},
			index:    0,
		},
		"remove middle": {
			origin:   []string{"a", "b", "c"},
			expected: []string{"a", "c"},
			index:    1,
		},
		"remove end": {
			origin:   []string{"a", "b", "c"},
			expected: []string{"a", "b"},
			index:    2,
		},
	}

	for i, v := range tests {
		RemoveIndexFromStringSlice(&v.origin, v.index)
		assert.Equal(t, len(v.expected), len(v.origin), i)
		assert.Equal(t, v.expected, v.origin)
	}

}

func TestMergeSliceAndMap(t *testing.T) {
	type mapMergeTestCase struct {
		originSlice []string
		originMap   map[string]string
		expectedMap map[string]string
	}

	tests := map[string]mapMergeTestCase{
		"remove a single key": {
			originSlice: []string{"a", "b", "c"},
			originMap:   map[string]string{"a": "A", "c": "C", "d": "D"},
			expectedMap: map[string]string{"a": "A", "c": "C"},
		},
		"map should not change": {
			originSlice: []string{"a", "b", "c", "d"},
			originMap:   map[string]string{"a": "A", "c": "C", "d": "D"},
			expectedMap: map[string]string{"a": "A", "c": "C", "d": "D"},
		},
		"map should be empty": {
			originSlice: []string{"e", "f"},
			originMap:   map[string]string{"a": "A", "c": "C", "d": "D"},
			expectedMap: map[string]string{},
		},
		"empty slice": {
			originSlice: []string{},
			originMap:   map[string]string{"a": "A", "c": "C", "d": "D"},
			expectedMap: map[string]string{},
		},
		"empty map": {
			originSlice: []string{"e", "f"},
			originMap:   map[string]string{},
			expectedMap: map[string]string{},
		},
		"both are empty": {
			originSlice: []string{},
			originMap:   map[string]string{},
			expectedMap: map[string]string{},
		},
	}

	for i, v := range tests {
		r := MergeSliceAndMap(v.originSlice, v.originMap)
		assert.Equal(t, len(v.expectedMap), len(r), i)
		for k, v := range v.expectedMap {
			assert.Equal(t, v, r[k], i)
		}
	}
}
