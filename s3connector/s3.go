package s3connector

import (
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3Config struct {
	Endpoint    string `json:"endpoint"`
	Region      string `json:"region"`
	Bucket      string `json:"bucket"`
	AccessKey   string `json:"accessKey"`
	SecretKey   string `json:"secretKey"`
	Prefix      string `json:"prefix"`
	StorageType string `json:"storageType"`
}

type S3ObjectRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type S3ObjectPath struct {
	Bucket string         `json:"bucket"`
	Key    string         `json:"key"`
	Range  *S3ObjectRange `json:"range,omitempty"`
}

type ObjectStorage interface {
	StoreObject(objPath S3ObjectPath, value io.ReadSeeker) (S3ObjectPath, error)
	DeleteObject(S3ObjectPath) error
	GetObject(objPath S3ObjectPath) (io.ReadCloser, error)
	GetBucket() string
}

type s3ObjectStorage struct {
	ObjectStorage
	session      *session.Session
	bucket       string
	storageClass string
	prefix       string
}

func NewS3ObjectStorage(config S3Config) (ObjectStorage, error) {

	awsConf := &aws.Config{
		Region:           aws.String(config.Region),
		S3ForcePathStyle: aws.Bool(false),
	}

	if config.Endpoint != "" {
		awsConf.Endpoint = aws.String(config.Endpoint)
		awsConf.S3ForcePathStyle = aws.Bool(true)
	}

	if config.AccessKey != "" && config.SecretKey != "" {
		awsConf.Credentials = credentials.NewStaticCredentials(config.AccessKey, config.SecretKey, "")
	}
	session, err := session.NewSession(awsConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AWS session: %w", err)
	}

	s3ObjectStorageInstance := &s3ObjectStorage{session: session, bucket: config.Bucket, storageClass: config.StorageType, prefix: config.Prefix}

	// Check if the bucket exists
	if err = s3ObjectStorageInstance.BucketExists(config.Bucket); err != nil {
		return nil, fmt.Errorf("failed to check if bucket exists: %w", err)
	}

	return s3ObjectStorageInstance, nil
}

func (s *s3ObjectStorage) GetBucket() string {
	return s.bucket
}

func (s *s3ObjectStorage) BucketExists(bucket string) error {
	_, err := s3.New(s.session).HeadBucket(&s3.HeadBucketInput{Bucket: aws.String(bucket)})
	return err
}

func (s *s3ObjectStorage) StoreObject(objPath S3ObjectPath, value io.ReadSeeker) (S3ObjectPath, error) {

	fullKey := s.prefix + objPath.Key
	_, err := s3.New(s.session).PutObject(&s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(fullKey),
		StorageClass: aws.String(s.storageClass),
		Body:         value,
	})
	if err != nil {
		return S3ObjectPath{}, err
	}
	return S3ObjectPath{Key: fullKey}, nil
}

func (s *s3ObjectStorage) DeleteObject(objPath S3ObjectPath) error {
	_, err := s3.New(s.session).DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(objPath.Bucket),
		Key:    aws.String(objPath.Key),
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *s3ObjectStorage) GetObject(objPath S3ObjectPath) (io.ReadCloser, error) {

	var objRange *string

	if objPath.Range != nil {
		if objPath.Range.Start < 0 || objPath.Range.End <= objPath.Range.Start {
			return nil, fmt.Errorf("invalid range: start must be non-negative and end must be greater than start, ranges are: %v", objPath.Range)
		}
		objRange = aws.String(fmt.Sprintf("bytes=%d-%d", objPath.Range.Start, objPath.Range.End))
	}

	bucket := s.bucket
	if objPath.Bucket != "" {
		if err := s.BucketExists(objPath.Bucket); err != nil {
			return nil, fmt.Errorf("failed to GetObject, %w", err)
		} else {
			bucket = objPath.Bucket
		}

	}
	getObj := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objPath.Key),
		Range:  objRange,
	}
	if objPath.Range != nil && objPath.Range.Start > 0 && objPath.Range.End > 0 {
		getObj.Range = aws.String(fmt.Sprintf("bytes=%d-%d", objPath.Range.Start, objPath.Range.End))
	}
	awsObj, err := s3.New(s.session).GetObject(getObj)
	if err != nil {
		return nil, fmt.Errorf("failed to GetObject, %w", err)
	}
	return awsObj.Body, nil
}
