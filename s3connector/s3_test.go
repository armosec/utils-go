package s3connector

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type S3ObjectStorageSuite struct {
	suite.Suite
	EndPointPort        int
	randomContainerName string
	S3Localstack        *S3LocalStack
	shutdownFunc        func()
}

func TestS3ObjectStorage(t *testing.T) {
	suite.Run(t, new(S3ObjectStorageSuite))
}

func (suite *S3ObjectStorageSuite) SetupSuite() {
	suite.T().Log("setup suite")
	suite.EndPointPort = 4566

	objectName := "posture/resources/9a24c2bc-5bdb-4152-ae9c-1dcb66dd7c5b/5ca3f7c9-f4cc-4d44-a571-5b4c95985c75/rbac.authorization.k8s.io/v1//ClusterRoleBinding/system:controller:expand-controller"

	content := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"annotations":{"rbac.authorization.kubernetes.io/autoupdate":"true"},"creationTimestamp":"2023-08-07T11:53:12Z","labels":{"kubernetes.io/bootstrapping":"rbac-defaults"},"name":"system:controller:expand-controller","resourceVersion":"157","uid":"fa23adfc-e8ee-49b7-b956-1df6674c9a1a"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"system:controller:expand-controller"},"subjects":[{"kind":"ServiceAccount","name":"expand-controller","namespace":"kube-system"}]}`

	data := map[string]string{
		objectName: content,
	}
	localstack, err := NewS3LocalStack(data)

	if err != nil {
		suite.FailNow("failed to create new S3LocalStack", err.Error())
	}

	suite.S3Localstack = localstack
}

func (suite *S3ObjectStorageSuite) TearDownSuite() {
	suite.T().Log("tear down suite")
	suite.S3Localstack.ShutdownFunc()
}

func (suite *S3ObjectStorageSuite) TestGetObject() {
	res, err := suite.S3Localstack.GetLocalStack().GetObject(S3ObjectPath{
		Key: "posture/resources/9a24c2bc-5bdb-4152-ae9c-1dcb66dd7c5b/5ca3f7c9-f4cc-4d44-a571-5b4c95985c75/rbac.authorization.k8s.io/v1//ClusterRoleBinding/system:controller:expand-controller",
	})

	suite.NoError(err)
	suite.NotNil(res)
}

func (suite *S3ObjectStorageSuite) TestStoreObject() {
	objPath := S3ObjectPath{
		Key: "test",
	}
	res, err := suite.S3Localstack.GetLocalStack().StoreObject(objPath, bytes.NewReader([]byte("test")))
	suite.NoError(err)
	suite.NotNil(res)
}

func (suite *S3ObjectStorageSuite) TestDeleteObject() {
	err := suite.S3Localstack.GetLocalStack().DeleteObject("test1")
	suite.NoError(err)

	res, err := suite.S3Localstack.GetLocalStack().GetObject(S3ObjectPath{
		Key: "test",
	})
	suite.Error(err)
	assert.Contains(suite.T(), err.Error(), "failed to GetObject, NoSuchKey: The specified key does not exist")
	suite.Nil(res)
}

func (suite *S3ObjectStorageSuite) TestGetByRange() {
	// Setup
	key := "range_test_object"
	fullContent := "Hello, this is a range test content"
	start := int64(7) // Starting byte position (inclusive)
	end := int64(22)  // Ending byte position (inclusive)

	// Store the test object
	_, err := suite.S3Localstack.GetLocalStack().StoreObject(S3ObjectPath{Key: key}, bytes.NewReader([]byte(fullContent)))
	suite.NoError(err)

	// Perform the GetByRange operation
	res, err := suite.S3Localstack.GetLocalStack().GetByRange(S3ObjectPath{Key: key}, start, end)
	suite.NoError(err)
	suite.NotNil(res)

	// Read and verify the content
	rangeContent, err := ioutil.ReadAll(res)
	suite.NoError(err)
	expectedContent := fullContent[start : end+1] // +1 because the end index is inclusive
	suite.Equal(expectedContent, string(rangeContent))

	// Clean up
	err = suite.S3Localstack.GetLocalStack().DeleteObject(key)
	suite.NoError(err)
}
