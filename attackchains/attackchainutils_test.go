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
	}{
		{
			name: "relevant - has relevancy data and relevant label is yes",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "yes",
				SeverityStats:    cscanlib.SeverityStats{Severity: "Critical"},
			},
			expected: true,
		},
		{
			name: "relevant - has relevancy data and relevant label is yes but not critical",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "yes",
				SeverityStats:    cscanlib.SeverityStats{Severity: "High"},
			},
			expected: false,
		},
		{
			name: "not relevant - has relevancy data and relevant label is no",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: true,
				RelevantLabel:    "no",
			},
			expected: false,
		},
		{
			name: "relevant - has no relevancy data and relevant label is no",
			vul: &cscanlib.CommonContainerScanSummaryResult{
				ImageID:          "ss",
				HasRelevancyData: false,
				RelevantLabel:    "no",
				SeverityStats:    cscanlib.SeverityStats{Severity: "Critical"},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := isVulnarableRelevantToAttackChain(test.vul)
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
			actual, _ := validateWorkLoadMatch(test.vul, test.postureResourceSummary)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestConvertAttackTrackStepToAttackChainNode(t *testing.T) {

	control_1 := &reporthandling.Control{ControlID: "control_1",
		PortalBase: armotypes.PortalBase{
			Attributes: map[string]interface{}{
				"ContainerScanID": "ContainerScanID1",
				"vulnerabilities": []cscanlib.ShortVulnerabilityResult{},
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
			name: "attack step is not nil",
			step: &v1alpha1.AttackTrackStep{
				Name:     "test",
				Controls: []v1alpha1.IAttackTrackControl{control_1},
			},

			expected: &armotypes.AttackChainNode{
				Name:       "test",
				ControlIDs: []string{"control_1"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := ConvertAttackTrackStepToAttackChainNode(test.step)
			if !(test.expected == nil && actual == nil) {
				assert.Equal(t, test.expected.Name, actual.Name, "expected and actual are not equal")
				assert.Equal(t, test.expected.ControlIDs, actual.ControlIDs, "expected and actual are not equal")
			}
		})
	}
}
