package str

import (
	"encoding/json"
	"strings"
)

// StringInSlice return true if string found in slice of strings
func StringInSlice(strSlice []string, str string) bool {
	for i := range strSlice {
		if strSlice[i] == str {
			return true
		}
	}
	return false
}

// StringInSliceCaseInsensitive return true if string found in slice of strings, ignore case sensitive
func StringInSliceCaseInsensitive(strSlice []string, str string) bool {
	for i := range strSlice {
		if strings.EqualFold(strSlice[i], str) {
			return true
		}
	}
	return false
}

// MapStringToSlice returns map's keys
func MapStringToSlice(strMap map[string]interface{}) []string {
	strSlice := []string{}
	for k := range strMap {
		strSlice = append(strSlice, k)
	}
	return strSlice
}

// SliceStringToUnique returns unique values of slice
func SliceStringToUnique(strSlice []string) []string {
	strMap := map[string]interface{}{}
	for i := range strSlice {
		strMap[strSlice[i]] = nil
	}
	return MapStringToSlice(strMap)
}

// RemoveIndexFromStringSlice -
func RemoveIndexFromStringSlice(s *[]string, index int) {
	(*s)[index] = (*s)[len(*s)-1]
	(*s)[len(*s)-1] = ""
	*s = (*s)[:len(*s)-1]
}

// MergeSliceAndMap merge a list and keys of map
func MergeSliceAndMap(s []string, m map[string]string) map[string]string {
	merged := make(map[string]string)
	for i := range s {
		if v, ok := m[s[i]]; ok {
			merged[s[i]] = v
		}
	}
	return merged
}

// ObjectToString Convert an object to a json string
func ObjectToString(obj interface{}) string {
	bm, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(bm)
}
