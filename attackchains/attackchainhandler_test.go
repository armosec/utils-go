package attackchains

import (
	"testing"

	"github.com/armosec/armoapi-go/containerscan"
	cscanlib "github.com/armosec/armoapi-go/containerscan"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/stretchr/testify/assert"
)

var allControls = AllControlsMock()

func TestDetectSingleAttackTrack(t *testing.T) {

	attackTrack1 := AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
		Name: "A",
		SubSteps: []v1alpha1.AttackTrackStep{
			{
				ChecksVulnerabilities: true,
				Name:                  "vulnerableImageStepName",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "C",
					},
					{
						Name: "D",
					},
				},
			},
			{
				Name: "E",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "B",
					},
				},
			},
		},
	})

	Attributes := map[string]string{"cluster": "minikubesecurity1",
		"kind":      "Pod",
		"name":      "wowtest",
		"namespace": "default"}

	tests := []struct {
		name            string
		attackTrack     v1alpha1.IAttackTrack
		FailedControls  []string
		WarningControls []string
		Vuls            []*cscanlib.CommonContainerScanSummaryResult
		Expected        v1alpha1.IAttackTrack
	}{
		{
			name:            "Attack chain exists with vulnarable image 'yes'",
			attackTrack:     attackTrack1,
			FailedControls:  []string{"control1", "control2"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelYes, Attributes),
			},

			Expected: AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						ChecksVulnerabilities: true,
						Name:                  "vulnerableImageStepName",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "C",
							},
						},
					},
				},
			}),
		},
		{
			name:            "Attack chain exists with vulnarable image no data",
			attackTrack:     attackTrack1,
			FailedControls:  []string{"control1", "control2"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(false, containerscan.RelevantLabelYes, Attributes),
			},

			Expected: AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						ChecksVulnerabilities: true,
						Name:                  "vulnerableImageStepName",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "C",
							},
						},
					},
				},
			}),
		},
		{
			name:            "Attack chain exists with 1 vulnarable image out of two",
			attackTrack:     attackTrack1,
			FailedControls:  []string{"control1", "control2"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelNo, Attributes),
				CommonContainerScanSummaryResultMock(false, containerscan.RelevantLabelYes, Attributes),
			},

			Expected: AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						ChecksVulnerabilities: true,
						Name:                  "vulnerableImageStepName",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "C",
							},
						},
					},
				},
			}),
		},
		{
			name:            "No Attack chain, no vulnarable image",
			attackTrack:     attackTrack1,
			FailedControls:  []string{"control1", "control2"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelNo, Attributes),
			},

			Expected: nil,
		},
		{
			name:            "Attack Chain exists, no vulnarable image",
			attackTrack:     attackTrack1,
			FailedControls:  []string{"control1", "control2"},
			WarningControls: []string{"control6"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelNo, Attributes),
			},

			Expected: AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "E",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "B",
							},
						},
					},
				},
			}),
		},
		{
			name:            "Attack chain exists with multiple paths, with vulnarable image 'yes'",
			attackTrack:     attackTrack1,
			FailedControls:  []string{"control1", "control2", "control6"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelYes, Attributes),
			},

			Expected: AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						ChecksVulnerabilities: true,
						Name:                  "vulnerableImageStepName",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "C",
							},
						},
					},
					{
						Name: "E",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "B",
							},
						},
					},
				},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			attackChainHandler, err := NewAttackChainHandler([]v1alpha1.IAttackTrack{test.attackTrack}, allControls)
			assert.NoError(t, err)

			postureResourcesSummary := PostureResourcesSummaryMock(Attributes, test.FailedControls, test.WarningControls)

			controlsLookup, err := attackChainHandler.getAttackTrackControlsLookup(postureResourcesSummary, test.Vuls)
			assert.NoError(t, err)
			attackChain, err := attackChainHandler.detectSingleAttackChain(test.attackTrack, controlsLookup)
			assert.NoError(t, err)
			if !(test.Expected == nil && attackChain == nil) {
				if test.Expected == nil {
					assert.Fail(t, "Expected is nil while actual is not nil")
				} else if attackChain == nil {
					assert.Fail(t, "Actual is nil while expected is not nil")
				} else {
					assert.True(t, attackChain.GetData().(*v1alpha1.AttackTrackStep).Equal(test.Expected.GetData().(*v1alpha1.AttackTrackStep), false))

				}
			}

		})

	}

}

func TestDetectAllAttackChains(t *testing.T) {

	Attributes := map[string]string{"cluster": "minikubesecurity1",
		"kind":      "Pod",
		"name":      "wowtest",
		"namespace": "default"}

	attackTrack1 := AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
		Name: "A",
		SubSteps: []v1alpha1.AttackTrackStep{
			{
				ChecksVulnerabilities: true,
				Name:                  "vulnerableImageStepName",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "C",
					},
					{
						Name: "D",
					},
				},
			},
			{
				Name: "E",
			},
		},
	})

	attackTrack2 := AttackTrackMock("attackchain2", v1alpha1.AttackTrackStep{
		Name: "A",
		SubSteps: []v1alpha1.AttackTrackStep{
			{
				Name: "B",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "C",
					},
					{
						Name: "D",
					},
				},
			},
			{
				Name: "E",
			},
		},
	})

	tests := []struct {
		name                 string
		attackTracks         []v1alpha1.IAttackTrack
		FailedControls       []string
		WarningControls      []string
		Vuls                 []*cscanlib.CommonContainerScanSummaryResult
		ExpectedAttackTracks []v1alpha1.IAttackTrack
	}{
		{
			name:            "Found one attack chain",
			attackTracks:    []v1alpha1.IAttackTrack{attackTrack1},
			FailedControls:  []string{"control1", "control2"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelYes, Attributes),
			},

			ExpectedAttackTracks: []v1alpha1.IAttackTrack{AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						ChecksVulnerabilities: true,
						Name:                  "vulnerableImageStepName",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "C",
							},
						},
					},
				},
			})},
		},
		{
			name:            "Found two attack chain",
			attackTracks:    []v1alpha1.IAttackTrack{attackTrack1, attackTrack2},
			FailedControls:  []string{"control1", "control2", "control6"},
			WarningControls: []string{"control3", "control4"},
			Vuls: []*cscanlib.CommonContainerScanSummaryResult{
				CommonContainerScanSummaryResultMock(true, containerscan.RelevantLabelYes, Attributes),
			},

			ExpectedAttackTracks: []v1alpha1.IAttackTrack{AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						ChecksVulnerabilities: true,
						Name:                  "vulnerableImageStepName",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name: "C",
							},
						},
					},
					{
						Name: "E",
					},
				},
			}),
				AttackTrackMock("attackchain2", v1alpha1.AttackTrackStep{
					Name: "A",
					SubSteps: []v1alpha1.AttackTrackStep{
						{
							Name: "B",
							SubSteps: []v1alpha1.AttackTrackStep{
								{
									Name: "C",
								},
							},
						},
						{
							Name: "E",
						},
					},
				})},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attackChainHandler, err := NewAttackChainHandler(test.attackTracks, allControls)
			assert.NoError(t, err)

			Attributes := map[string]string{"cluster": "minikubesecurity1",
				"kind":      "Pod",
				"name":      "wowtest",
				"namespace": "default"}

			postureResourcesSummary := PostureResourcesSummaryMock(Attributes, test.FailedControls, test.WarningControls)

			attackChains, err := attackChainHandler.DetectAllAttackChains(postureResourcesSummary, test.Vuls)

			assert.NoError(t, err)
			assert.Equalf(t, len(test.ExpectedAttackTracks), len(attackChains), "Expected and actual attack chains are not equal")

			for i := range attackChains {
				assert.Equal(t, attackChains[i].GetName(), test.ExpectedAttackTracks[i].GetName())
				assert.True(t, attackChains[i].GetData().(*v1alpha1.AttackTrackStep).Equal(test.ExpectedAttackTracks[i].GetData().(*v1alpha1.AttackTrackStep), false))
			}

		})

	}

}
