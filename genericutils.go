package goutils

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"strings"
)

//AsSHA256 takes anything turns it into string :) https://blog.8bitzen.com/posts/22-08-2019-how-to-hash-a-struct-in-go
func AsSHA256(v interface{}) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", v)))

	return fmt.Sprintf("%x", h.Sum(nil))
}

//AsFNVHash takes anything turns it into string :) https://blog.8bitzen.com/posts/22-08-2019-how-to-hash-a-struct-in-go
func AsFNVHash(v interface{}) string {
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%v", v)))
	return fmt.Sprintf("%d", h.Sum32())
}

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
	if strings.ToLower(s) == "true" || strings.ToLower(s) == "1" {
		return BoolPointer(true)
	}
	if strings.ToLower(s) == "false" || strings.ToLower(s) == "0" {
		return BoolPointer(false)
	}
	return nil
}
