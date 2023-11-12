package s3connector

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

type S3Mock struct {
	ObjectStorage
	storage map[string]string
	updated []string
	mux     sync.Mutex
}

func NewS3Mock() S3Mock {
	return S3Mock{
		storage: make(map[string]string),
		updated: []string{},
	}
}

func (s3 *S3Mock) DeleteObject(key string) error {
	s3.mux.Lock()
	defer s3.mux.Unlock()
	delete(s3.storage, key)
	return nil
}

func (s3 *S3Mock) GetBucket() string {
	return "no-bucket"
}

func (s3 *S3Mock) GetObject(objPath S3ObjectPath) (io.ReadCloser, error) {
	s3.mux.Lock()
	defer s3.mux.Unlock()
	if obj, ok := s3.storage[objPath.Key]; ok {
		return io.NopCloser(bytes.NewReader([]byte(obj))), nil
	}
	return nil, fmt.Errorf("not found")
}

func (s3 *S3Mock) GetStorageLen() int {
	s3.mux.Lock()
	defer s3.mux.Unlock()
	return len(s3.storage)
}

func (s3 *S3Mock) GetUpdatedLen() int {
	s3.mux.Lock()
	defer s3.mux.Unlock()
	return len(s3.updated)
}

func (s3 *S3Mock) StoreObject(key string, value io.ReadSeeker) (S3ObjectPath, error) {
	s3.mux.Lock()
	defer s3.mux.Unlock()
	if _, ok := s3.storage[key]; ok {
		s3.updated = append(s3.updated, key)
	}
	bytes, err := io.ReadAll(value)
	if err != nil {
		return S3ObjectPath{}, fmt.Errorf("failed to read bytes: %w", err)
	}
	if len(bytes) == 0 {
		return S3ObjectPath{}, fmt.Errorf("empty bytes")
	}
	s3.storage[key] = string(bytes)
	return S3ObjectPath{Key: key}, nil
}

func (s3 *S3Mock) Reset() {
	s3.mux.Lock()
	defer s3.mux.Unlock()
	s3.storage = make(map[string]string)
	s3.updated = []string{}
}
