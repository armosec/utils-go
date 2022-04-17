package boolutils

import (
	"strings"
)

func BoolPointer(b bool) *bool { return &b }

func BoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func BoolPointerToString(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

func StringToBool(s string) bool {
	if strings.ToLower(s) == "true" || strings.ToLower(s) == "1" {
		return true
	}
	return false
}

func StringToBoolPointer(s string) *bool {
	if strings.ToLower(s) == "false" || strings.ToLower(s) == "0" {
		return BoolPointer(false)
	}
	if strings.ToLower(s) == "true" || strings.ToLower(s) != "0" {
		return BoolPointer(true)
	}
	return nil
}
