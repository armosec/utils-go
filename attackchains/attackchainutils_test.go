package attackchains

import (
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	cscanlib "github.com/armosec/armoapi-go/containerscan"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"

	"github.com/stretchr/testify/assert"
)

func TestIsVulnarableRelevantToAttackChange(t *testing.T) {
	tests := []struct {
		name     string
		vul      *cscanlib.CommonContainerScanSummaryResult
		expected bool
		wantErr  bool
	}{
		{
			name: "relevant - has relevancy data and relevant label is yes",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "yes",
				SeveritiesStats:  []cscanlib.SeverityStats{{Severity: "Critical", RelevantCount: 1}},
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "relevant - has relevancy data and relevant label is yes but not critical",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "yes",
				SeveritiesStats:  []cscanlib.SeverityStats{{Severity: "High", RelevantCount: 1}},
			},
			expected: false,
			wantErr:  false,
		},
		{
			name: "not relevant - has relevancy data and relevant label is no",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "no",
				SeveritiesStats:  []cscanlib.SeverityStats{{Severity: "High", RelevantCount: 1}},
			},
			expected: false,
			wantErr:  false,
		},
		{
			name: "relevant - has no relevancy data and relevant label is no",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: false,
				RelevantLabel:    "no",
				SeveritiesStats:  []cscanlib.SeverityStats{{Severity: "Critical", RelevantCount: 0, TotalCount: 1}},
			},
			expected: true,
			wantErr:  false,
		},
		{
			name: "relevant - has no relevancy data and relevant count is 0",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "yes",
				SeveritiesStats:  []cscanlib.SeverityStats{{Severity: "Critical", RelevantCount: 0}},
			},
			expected: false,
			wantErr:  false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := isVulnerableRelevantToAttackChain(test.vul)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestIsSupportedKind(t *testing.T) {
	assert.True(t, isSupportedKind("Deployment"))
	assert.True(t, isSupportedKind("Pod"))
	assert.True(t, isSupportedKind("Node"))
	assert.True(t, isSupportedKind("DaemonSet"))
	assert.True(t, isSupportedKind("StatefulSet"))
	assert.True(t, isSupportedKind("Job"))
	assert.True(t, isSupportedKind("CronJob"))
	assert.False(t, isSupportedKind(""))
	assert.False(t, isSupportedKind("ConfigMap"))
	assert.False(t, isSupportedKind("ServiceAccount"))
}

func TestValidateWorkLoadMatch(t *testing.T) {
	tests := []struct {
		name                   string
		vul                    *cscanlib.CommonContainerScanSummaryResult
		postureResourceSummary *armotypes.PostureResourceSummary
		expected               bool
	}{
		{
			name: "resource key matches",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				Designators: identifiers.PortalDesignator{
					Attributes: map[string]string{"kind": "Deployment", "name": "test", "namespace": "default", "cluster": "minikube"},
				},
			},
			postureResourceSummary: &armotypes.PostureResourceSummary{
				Designators: identifiers.PortalDesignator{
					Attributes: map[string]string{"kind": "Deployment", "name": "test", "namespace": "default", "cluster": "minikube"},
				},
			},
			expected: true,
		},
		{
			name: "resource key does not match",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				Designators: identifiers.PortalDesignator{
					Attributes: map[string]string{"kind": "Deployment", "name": "test1", "namespace": "default", "cluster": "minikube"},
				},
			},
			postureResourceSummary: &armotypes.PostureResourceSummary{
				Designators: identifiers.PortalDesignator{
					Attributes: map[string]string{"kind": "Deployment", "name": "test2", "namespace": "default", "cluster": "minikube"},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := validateWorkLoadMatch(test.postureResourceSummary, test.vul)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestConvertAttackTrackStepToAttackChainNode(t *testing.T) {

	control_1 := &reporthandling.Control{ControlID: "control_1",
		PortalBase: armotypes.PortalBase{
			Attributes: map[string]interface{}{
				identifiers.AttributeContainerScanId: "ContainerScanID1",
				identifiers.AttributeContainerName:   "ContainerName1",
				"vulnerabilities":                    []cscanlib.ShortVulnerabilityResult{{Name: "CVE1"}},
			},
		}}

	tests := []struct {
		name     string
		step     *v1alpha1.AttackTrackStep
		expected *armotypes.AttackChainNode
	}{
		{
			name:     "attack step is nil",
			step:     &v1alpha1.AttackTrackStep{},
			expected: nil,
		},
		{
			name: "attack step is empty",
			step: &v1alpha1.AttackTrackStep{
				Name:                  "test",
				ChecksVulnerabilities: true,
				Controls:              []v1alpha1.IAttackTrackControl{control_1},
			},

			expected: &armotypes.AttackChainNode{
				Name:       "test",
				ControlIDs: nil,
			},
		},
		{
			name: "attack step is not nil, not vul",
			step: &v1alpha1.AttackTrackStep{
				Name:     "test",
				Controls: []v1alpha1.IAttackTrackControl{control_1},
			},

			expected: &armotypes.AttackChainNode{
				Name:       "test",
				ControlIDs: []string{"control_1"},
			},
		},
		{
			name: "attack step is not nil, vul",
			step: &v1alpha1.AttackTrackStep{
				Name:                  "test",
				ChecksVulnerabilities: true,
				Controls:              []v1alpha1.IAttackTrackControl{control_1},
			},

			expected: &armotypes.AttackChainNode{
				Name: "test",
				Vulnerabilities: []armotypes.Vulnerabilities{
					{
						ContainerName: "ContainerName1",
						ImageScanID:   "ContainerScanID1",
						Names:         []string{"CVE1"},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := ConvertAttackTrackStepToAttackChainNode(test.step)
			if !(test.expected == nil && actual == nil) {
				assert.Equal(t, test.expected.Name, actual.Name, "expected and actual are not equal")
				assert.Equal(t, test.expected.ControlIDs, actual.ControlIDs, "expected and actual are not equal")
				if test.expected.Vulnerabilities != nil {
					assert.Equal(t, test.expected.Vulnerabilities[0].ContainerName, actual.Vulnerabilities[0].ContainerName, "expected and actual are not equal")
				}
			}
		})
	}
}

func TestGenerateAttackChainID(t *testing.T) {
	// Test cases
	testCases := []struct {
		name                  string
		customerGUID          string
		attackTrackName       string
		cluster               string
		apiVersion            string
		namespace             string
		kind                  string
		resourceName          string
		expectedAttackChainID string
	}{
		{
			name:                  "Test case 1",
			customerGUID:          "1234567890",
			attackTrackName:       "service-destruction",
			cluster:               "cluster1",
			apiVersion:            "v1",
			namespace:             "default",
			kind:                  "Deployment",
			resourceName:          "my-deployment",
			expectedAttackChainID: "3257300354",
		},
		{
			name:                  "Test case 1",
			customerGUID:          "1234567890",
			attackTrackName:       "workload-external-track",
			cluster:               "cluster2",
			apiVersion:            "v1",
			namespace:             "default",
			kind:                  "Pod",
			resourceName:          "my-pod",
			expectedAttackChainID: "1331301378",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock postureResourceSummary for testing
			mockResourceSummary := &armotypes.PostureResourceSummary{
				Designators: identifiers.PortalDesignator{
					Attributes: map[string]string{
						"cluster":    tc.cluster,
						"apiVersion": tc.apiVersion,
						"namespace":  tc.namespace,
						"kind":       tc.kind,
						"name":       tc.resourceName,
					},
				},
			}

			// Call the function to get the actual attackChainID
			actualAttackChainID := GenerateAttackChainID(tc.customerGUID, tc.attackTrackName, mockResourceSummary.Designators.Attributes)

			// Check if the actual value matches the expected value
			assert.Equal(t, tc.expectedAttackChainID, actualAttackChainID)
		})
	}
}
