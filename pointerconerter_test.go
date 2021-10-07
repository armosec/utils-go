package goutils

import "testing"

func TestBoolToString(t *testing.T) {
	if BoolToString(true) != "true" {
		t.Errorf("expected: true")
	}
	if BoolToString(false) != "false" {
		t.Errorf("expected: false")
	}
}

func TestBoolPointerToString(t *testing.T) {
	tr := true
	if BoolPointerToString(&tr) != "true" {
		t.Errorf("expected: true")
	}
	f := false
	if BoolPointerToString(&f) != "false" {
		t.Errorf("expected: false")
	}
}

func TestStringToBool(t *testing.T) {
	if !StringToBool("true") {
		t.Errorf("expected: true")
	}
	if StringToBool("false") {
		t.Errorf("expected: false")
	}
}

func TestStringToBoolPointer(t *testing.T) {
	if !*StringToBoolPointer("true") {
		t.Errorf("expected: true")
	}
	if *StringToBoolPointer("false") {
		t.Errorf("expected: false")
	}
}
