package attackchains

import (
	_ "embed"
	"encoding/json"
	"strings"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	cscanlib "github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/google/uuid"

	// csscan "github.com/armosec/cluster-container-scanner-api"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

//go:embed testdata/attacktracks/workload_external_track.json
var attackTrackWorkloadExternalTrack string

//go:embed testdata/attacktracks/service_destruction.json
var attackTrackServiceDestruction string

func AllControlsMock() map[string]*reporthandling.Control {
	controlsInfo := make(map[string]*reporthandling.Control)
	controlsInfo["control1"] = ControlMock("control1", []string{"attackchain1", "attackchain2"}, 1, []string{securityFrameworkName}, []string{"A"})
	controlsInfo["control2"] = ControlMock("control2", []string{"attackchain1", "attackchain2"}, 1, []string{securityFrameworkName}, []string{"B"})
	controlsInfo["control3"] = ControlMock("control3", []string{"attackchain1", "attackchain2"}, 1, []string{securityFrameworkName}, []string{"C"})
	controlsInfo["control4"] = ControlMock("control4", []string{"attackchain1", "attackchain2"}, 1, []string{securityFrameworkName}, []string{"C"})
	controlsInfo["control5"] = ControlMock("control5", []string{"attackchain1", "attackchain2"}, 1, []string{securityFrameworkName}, []string{"D"})
	controlsInfo["control6"] = ControlMock("control6", []string{"attackchain1", "attackchain2"}, 1, []string{securityFrameworkName}, []string{"E"})

	return controlsInfo
}

func ControlMock(id string, attackTrackNames []string, baseScore float32, tags []string, categories []string) *reporthandling.Control {
	control := &reporthandling.Control{
		ControlID: id,
		BaseScore: baseScore,
		PortalBase: armotypes.PortalBase{
			Attributes: map[string]interface{}{
				"controlTypeTags": tags,
			},
		},
	}

	attackTrackCategories := make([]reporthandling.AttackTrackCategories, 0)

	for _, attackTrackName := range attackTrackNames {
		attackTrackCategories = append(attackTrackCategories, reporthandling.AttackTrackCategories{AttackTrack: attackTrackName, Categories: categories})
	}

	control.Attributes["attackTracks"] = attackTrackCategories

	return control
}

// attributes for wl info (kind, cluster, namespace, name. SPIFF as identity?  etc)
// v1-raw-resources-report (no need?)
// v3-containerscan-vul for images
// enrichResourceSummaryFromRegoStore - might extend the function on backend for attack-chain purpose.
func PostureResourcesSummaryMock(attributes map[string]string, failedControlIds []string, warningControlIds []string) *armotypes.PostureResourceSummary {
	postureResourceSummary := armotypes.PostureResourceSummary{
		Designators:         armotypes.PortalDesignator{Attributes: attributes},
		ResourceKind:        attributes["kind"],
		FailedControl:       failedControlIds,
		WarningControls:     warningControlIds,
		FailedControlCount:  len(failedControlIds),
		SkippedControlCount: len(warningControlIds),
		ReportID:            uuid.New().String(),
	}

	postureResourceSummary.ResourceID = GenerateResourceIDMock(&postureResourceSummary)

	return &postureResourceSummary
}

func CommonContainerScanSummaryResultMock(hasRelevancyData bool, relevantLabel cscanlib.RelevantLabel, attributes map[string]string) *cscanlib.CommonContainerScanSummaryResult {
	vuls := []cscanlib.ShortVulnerabilityResult{
		{Name: "CVE-1"},
		{Name: "CVE-2"},
		{Name: "CVE-3"},
	}

	ImageHash := "ImageID_" + uuid.New().String()

	return &cscanlib.CommonContainerScanSummaryResult{
		ImageID:          ImageHash,
		HasRelevancyData: hasRelevancyData,
		RelevantLabel:    relevantLabel,
		Designators: armotypes.PortalDesignator{
			Attributes: attributes,
		},
		Vulnerabilities: vuls,
		ContainerScanID: uuid.New().String(),
		SeverityStats:   cscanlib.SeverityStats{Severity: "Critical"},
	}
}

func AttackTrackMock(name string, data v1alpha1.AttackTrackStep) *v1alpha1.AttackTrack {
	at := v1alpha1.AttackTrack{}
	at.Metadata = make(map[string]interface{})
	at.Metadata["name"] = name
	at.Spec.Version = "1.0"
	at.Spec.Data = data
	return &at
}

// AttackTrackMock1 is a mock of attack track with 3 levels, without image vulnerability
func AttackTrackMock1() v1alpha1.IAttackTrack {
	return AttackTrackMock("attackchain1", v1alpha1.AttackTrackStep{
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
}

// AttackTrackMock2 is a mock of attack track with 1 level, without image vulnerability
func AttackTrackMock2() v1alpha1.IAttackTrack {

	return AttackTrackMock("attackchain2", v1alpha1.AttackTrackStep{
		Name: "Z",
	})

}

// AttackTrackMock3 is a mock of attack track with 3 levels, without image vulnerability
func AttackTrackMock3() v1alpha1.IAttackTrack {
	return AttackTrackMock("attackchain3", v1alpha1.AttackTrackStep{
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
}

func AttackTracksMocks() []v1alpha1.IAttackTrack {
	mock1 := AttackTrackMock1()
	mock2 := AttackTrackMock2()
	mock3 := AttackTrackMock3()
	return []v1alpha1.IAttackTrack{mock1, mock2, mock3}
}

func GetControlsMocks() map[string]*reporthandling.Control {
	controlsInfo := make(map[string]*reporthandling.Control)
	controlsInfo["control1"] = ControlMock("control1", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Workload Exposure"})
	controlsInfo["control2"] = ControlMock("control2", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Data Access"})
	controlsInfo["control3"] = ControlMock("control3", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Secret Access"})
	controlsInfo["control4"] = ControlMock("control4", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Credential access"})
	controlsInfo["control5"] = ControlMock("control5", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Potential Node exposure"})
	controlsInfo["control6"] = ControlMock("control6", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Persistence"})
	controlsInfo["control7"] = ControlMock("control7", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Network"})
	controlsInfo["control8"] = ControlMock("control8", []string{"workload-external-track", "service-destruction"}, 1, []string{securityFrameworkName}, []string{"Service Destruction"})

	return controlsInfo
}

func GetAttackTrackMocks() ([]v1alpha1.AttackTrack, error) {

	attackTracksMocks := []string{attackTrackWorkloadExternalTrack,
		attackTrackServiceDestruction}

	attackTracks := []v1alpha1.AttackTrack{}

	for _, attackTrackMock := range attackTracksMocks {
		attackTrack := &v1alpha1.AttackTrack{}
		err := json.Unmarshal([]byte(attackTrackMock), &attackTrack)

		if err != nil {
			return nil, err
		}

		attackTracks = append(attackTracks, *attackTrack)
	}

	return attackTracks, nil
}

func GetAttackTrackInputMocks() ([]*armotypes.PostureResourceSummary, []*cscanlib.CommonContainerScanSummaryResult) {
	var postureResourceSummaries []*armotypes.PostureResourceSummary
	var vuls []*cscanlib.CommonContainerScanSummaryResult

	failedControls := []string{"control1", "control7", "control8"}
	warningControls := []string{"control2"}

	Attributes := []map[string]string{
		{"apiVersion": "apps/v1",
			"cluster":   "testmock1",
			"kind":      "Pod",
			"name":      "podtest1",
			"namespace": "default"},
		{"apiVersion": "apps/v1",
			"cluster":   "testmock1",
			"kind":      "Deployment",
			"name":      "deploymenttest1",
			"namespace": "default"},
		{"apiVersion": "apps/v1",
			"cluster":   "testmock2",
			"kind":      "Deployment",
			"name":      "deploymenttest2",
			"namespace": "default"}}

	for _, attributes := range Attributes {

		postureResourcesSummary := PostureResourcesSummaryMock(attributes, failedControls, warningControls)
		commonContainerScanSummaryResult := CommonContainerScanSummaryResultMock(true, "yes", attributes)

		postureResourceSummaries = append(postureResourceSummaries, postureResourcesSummary)
		vuls = append(vuls, commonContainerScanSummaryResult)
	}

	return postureResourceSummaries, vuls

}

// GenerateResourceIDMock generates attackChainID
// structure: apiVersion/namespace/kind/name
func GenerateResourceIDMock(postureResourceSummary *armotypes.PostureResourceSummary) string {
	attributes := postureResourceSummary.Designators.Attributes
	elements := []string{attributes["apiVersion"], attributes["namespace"], attributes["kind"], attributes["name"]}
	return strings.Join(elements, "/")
}
