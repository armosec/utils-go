package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoolToString(t *testing.T) {
	assert.Equal(t, BoolToString(true), "true")
	assert.Equal(t, BoolToString(false), "false")
}

func TestBoolPointerToString(t *testing.T) {
	tr := true
	assert.Equal(t, BoolPointerToString(&tr), "true")

	f := false
	assert.Equal(t, BoolPointerToString(&f), "false")
}

func TestStringToBool(t *testing.T) {
	assert.True(t, StringToBool("true"))
	assert.False(t, StringToBool("false"))
}

func TestStringToBoolPointer(t *testing.T) {
	assert.True(t, *StringToBoolPointer("true"))
	assert.False(t, *StringToBoolPointer("false"))
}
