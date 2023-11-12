package s3connector

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNewS3Mock(t *testing.T) {
	mock := NewS3Mock()
	if len(mock.storage) != 0 || len(mock.updated) != 0 {
		t.Errorf("New S3Mock should have empty storage and updated slices")
	}
}

func TestS3Mock_StoreObject(t *testing.T) {
	mock := NewS3Mock()
	key := "testKey"
	objPath := S3ObjectPath{Key: key}

	value := strings.NewReader("testValue")

	// Store new object
	_, err := mock.StoreObject(objPath, value)
	if err != nil {
		t.Errorf("Failed to store object: %s", err)
	}
	if mock.storage[key] != "testValue" {
		t.Errorf("Object not stored correctly")
	}

	// Store object with existing key
	_, err = mock.StoreObject(objPath, strings.NewReader("testValue"))
	if err != nil {
		t.Errorf("Failed to store object with existing key: %s", err)
	}
	if len(mock.updated) != 1 || mock.updated[0] != key {
		t.Errorf("Updated slice not updated correctly")
	}

	// Test error on empty bytes
	_, err = mock.StoreObject(objPath, bytes.NewReader(nil))
	if err == nil {
		t.Errorf("Expected error on empty bytes, got none")
	}
}

func TestS3Mock_GetObject(t *testing.T) {
	mock := NewS3Mock()
	mock.storage["existingKey"] = "existingValue"

	// Test retrieving existing object
	reader, err := mock.GetObject(S3ObjectPath{Key: "existingKey"})
	if err != nil {
		t.Errorf("Failed to get object: %s", err)
	}
	bytes, _ := io.ReadAll(reader)
	if string(bytes) != "existingValue" {
		t.Errorf("GetObject returned incorrect value")
	}

	// Test retrieving non-existing object
	_, err = mock.GetObject(S3ObjectPath{Key: "nonExistingKey"})
	if err == nil {
		t.Errorf("Expected error when getting non-existing object, got none")
	}
}

func TestS3Mock_DeleteObject(t *testing.T) {
	mock := NewS3Mock()
	mock.storage["keyToDelete"] = "value"

	// Test deleting existing object
	err := mock.DeleteObject("keyToDelete")
	if err != nil {
		t.Errorf("Failed to delete object: %s", err)
	}
	if _, exists := mock.storage["keyToDelete"]; exists {
		t.Errorf("Object was not deleted")
	}
}

func TestS3Mock_GetStorageLen(t *testing.T) {
	mock := NewS3Mock()
	mock.storage["key1"] = "value1"
	mock.storage["key2"] = "value2"

	if mock.GetStorageLen() != 2 {
		t.Errorf("GetStorageLen returned incorrect length")
	}
}

func TestS3Mock_GetUpdatedLen(t *testing.T) {
	mock := NewS3Mock()
	mock.updated = append(mock.updated, "key1")

	if mock.GetUpdatedLen() != 1 {
		t.Errorf("GetUpdatedLen returned incorrect length")
	}
}

func TestS3Mock_Reset(t *testing.T) {
	mock := NewS3Mock()
	mock.storage["key"] = "value"
	mock.updated = append(mock.updated, "key")

	mock.Reset()

	if len(mock.storage) != 0 || len(mock.updated) != 0 {
		t.Errorf("Reset did not clear storage and updated slices")
	}
}
