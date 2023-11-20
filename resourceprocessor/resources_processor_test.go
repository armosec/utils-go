package resourceprocessor

import (
	"testing"

	s3connector "github.com/armosec/utils-go/s3connector"
	postgresconnector "github.com/kubescape/postgres-connector/dal"

	"github.com/stretchr/testify/suite"
)

func TestResourceProcessorTestSuite(t *testing.T) {
	suite.Run(t, new(ResourceProcessorTestSuite))
}

type ResourceProcessorTestSuite struct {
	postgresconnector.PostgresConnectorTestSuite
	s3    s3connector.S3Mock
	suite *suite.Suite
}

func (suite *ResourceProcessorTestSuite) SetupSuite() {
	suite.PostgresConnectorTestSuite.SetupSuite()
	suite.s3 = s3connector.NewS3Mock()
}

func (suite *ResourceProcessorTestSuite) TearDownTest() {
	suite.PostgresConnectorTestSuite.TearDownSuite()
	suite.s3.Reset()
}

func (suite *ResourceProcessorTestSuite) TestResourceProcessor() {

	customerGUID := "test-customer-guid"

	processor := NewKubernetesResourceProcessor(&suite.s3, suite.GetPostgresDAL())
	kind := "test-kind"
	cluster := "test-cluster"
	name := "test-name"
	namespace := "test-namespace"

	testData := []byte(`{
						"apiVersion": 
						"v1","kind": "test-kind",
						 "metadata": 
						 	{
								"name": "test-name", 
								"namespace": "test-namespace", 
								"labels": 
									{
										"test-label": "test-value"
									},
								"creationTimestamp": "2023-11-16T10:15:05Z"
							}
						}`)

	// identity := map[string]string{"cluster": "test-cluster", "kind": kind, "name": "test-name", "namespace": "test-namespace", "customerGUID": customerGUID}

	err := processor.Store(customerGUID, cluster, kind, namespace, name, testData)
	if err != nil {
		suite.FailNow(err.Error())
	}

	res, objectBytes, err := processor.Get(customerGUID, cluster, kind, namespace, name)
	suite.NoError(err)
	suite.Assert().Equal(testData, objectBytes)
	suite.Assert().NotNil(res)

	// Test Patch
	patchedData := []byte(`{
							"apiVersion": 
							"v2","kind": "test-kind",
							"metadata": 
								{
									"name": "test-name", 
									"namespace": "test-namespace", 
									"labels": 
										{
											"test-label": "test-value"
										},
									"creationTimestamp": "2023-11-16T10:15:05Z"
								}
							}`)

	err = processor.Patch(customerGUID, cluster, kind, namespace, name, patchedData)
	suite.NoError(err)

	res, objectBytes, err = processor.Get(customerGUID, cluster, kind, namespace, name)
	suite.NoError(err)
	suite.Assert().Equal(patchedData, objectBytes)

	// Test Delete
	err = processor.Delete(customerGUID, cluster, kind, namespace, name)
	suite.NoError(err)

	res, objectBytes, err = processor.Get(customerGUID, cluster, kind, namespace, name)
	suite.Error(err)
	suite.Assert().Nil(res)

	// Test GetObjectFromS3 not found
	objPath := s3connector.S3ObjectPath{
		Bucket: "test-bucket",
		Key:    "I_dont_exist",
	}
	_, err = processor.GetObjectFromS3(objPath)
	suite.Error(err)
}
