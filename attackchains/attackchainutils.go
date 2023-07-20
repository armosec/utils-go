package attackchains

import (
	"fmt"
	"strings"
	"time"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	cscanlib "github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/google/uuid"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

func isSupportedKind(kind string) bool {
	switch kind {
	case "Deployment",
		"Pod",
		"ReplicaSet",
		"Node",
		"DaemonSet",
		"StatefulSet",
		"Job",
		"CronJob":
		return true
	}

	return false
}

// convertVulToControl - convert vulnarability to control object. This is done in order to unify the way we handle vulnarabilities and controls when generating the attack chains.
func convertVulToControl(vul *cscanlib.CommonContainerScanSummaryResult, tags []string, attackTracks []v1alpha1.IAttackTrack) *reporthandling.Control {
	if vul == nil {
		return nil
	}

	attackTrackCategories := make([]reporthandling.AttackTrackCategories, 0, len(attackTracks))
	for _, attackTrack := range attackTracks {
		stepNamesWithVulnerabilities := attackTrack.GetSubstepsWithVulnerabilities()

		if len(stepNamesWithVulnerabilities) == 0 {
			continue
		}

		attackTrackCategories = append(attackTrackCategories, reporthandling.AttackTrackCategories{
			AttackTrack: attackTrack.GetName(),
			Categories:  stepNamesWithVulnerabilities,
		})

	}

	return &reporthandling.Control{
		ControlID: vul.ImageID,
		PortalBase: armotypes.PortalBase{
			Attributes: map[string]interface{}{
				"controlTypeTags": tags,
				"attackTracks":    attackTrackCategories,
				"vulnerabilities": vul.Vulnerabilities,
				"ContainerScanID": vul.ContainerScanID,
			},
		},
	}
}

// isVulnarableRelevantToAttackChain checks if the vulnarability is relevant to the attack chain
func isVulnarableRelevantToAttackChain(vul *cscanlib.CommonContainerScanSummaryResult) bool {
	return (!vul.HasRelevancyData || (vul.HasRelevancyData && vul.RelevantLabel == "yes")) && vul.Severity == "Critical"
}

// validateWorkLoadMatch checks if the vulnarability and the posture resource summary are of the same workload
func validateWorkLoadMatch(vul *cscanlib.CommonContainerScanSummaryResult, postureResourceSummary *armotypes.PostureResourceSummary) (bool, error) {

	vulResourceID := vul.Designators.Attributes["cluster"] + "_" + vul.Designators.Attributes["kind"] + "_" + vul.Designators.Attributes["namespace"] + "_" + vul.Designators.Attributes["name"]
	postureResourceSummaryResourceID := postureResourceSummary.Designators.Attributes["cluster"] + "_" + postureResourceSummary.Designators.Attributes["kind"] + "_" + postureResourceSummary.Designators.Attributes["namespace"] + "_" + postureResourceSummary.Designators.Attributes["name"]

	if vulResourceID != postureResourceSummaryResourceID {
		return false, fmt.Errorf("vul resource id %s does not match posture resource id %s", vulResourceID, postureResourceSummaryResourceID)
	}

	return true, nil
}

func ConvertAttackTracksToAttackChains(attacktracks []v1alpha1.IAttackTrack, postureResourceSummary *armotypes.PostureResourceSummary) []*armotypes.AttackChain {
	var attackChains []*armotypes.AttackChain
	for _, attackTrack := range attacktracks {
		attackChains = append(attackChains, ConvertAttackTrackToAttackChain(attackTrack, postureResourceSummary))
	}
	return attackChains

}

func ConvertAttackTrackToAttackChain(attackTrack v1alpha1.IAttackTrack, postureResourceSummary *armotypes.PostureResourceSummary) *armotypes.AttackChain {
	var chainNodes = ConvertAttackTrackStepToAttackChainNode(attackTrack.GetData())
	return &armotypes.AttackChain{
		Type: &armotypes.AttackChainType{
			Name:        attackTrack.GetName(),
			Description: attackTrack.GetDescription(),
		},
		ClusterName:      postureResourceSummary.Designators.Attributes["cluster"],
		Resource:         armotypes.PortalDesignator{DesignatorType: armotypes.DesignatorAttributes, Attributes: postureResourceSummary.Designators.Attributes}, // Update this with your actual logic
		AttackChainID:    GenerateAttackChainID(attackTrack, postureResourceSummary),                                                                            // Update this with your actual logic
		CustomerGUID:     uuid.New().String(),                                                                                                                   // Update this with your actual logic
		AttackChainNodes: *chainNodes,
		UIStatus:         &armotypes.AttackChainUIStatus{FirstSeen: time.Now().String()},
		LatestReportGUID: postureResourceSummary.ReportID,
	}
}

func ConvertAttackTrackStepToAttackChainNode(step v1alpha1.IAttackTrackStep) *armotypes.AttackChainNode {
	var controlIDs []string
	var imageVulnerabilities []armotypes.Vulnerabilities

	if step.GetName() == "" {
		return nil
	}

	if step.DoesCheckVulnerabilities() {
		for _, vulControl := range step.GetControls() {
			containerScanID := vulControl.(*reporthandling.Control).Attributes["ContainerScanID"].(string)
			vulnerabilities := vulControl.(*reporthandling.Control).Attributes["vulnerabilities"].([]cscanlib.ShortVulnerabilityResult)
			for _, vul := range vulnerabilities {
				imageVulnerabilities = append(imageVulnerabilities, armotypes.Vulnerabilities{ContainersScanID: containerScanID, Names: []string{vul.Name}})
			}

		}
	} else {
		// If the step does not check vulnerabilities, it means it is a step that checks controls.
		// for steps checks vulnerabilities, we don't add the controls as they were used only for the step detection.
		for _, control := range step.GetControls() {
			controlIDs = append(controlIDs, control.GetControlId())
		}
	}

	var nextNodes []armotypes.AttackChainNode
	for i := 0; i < step.Length(); i++ {
		nextNode := ConvertAttackTrackStepToAttackChainNode(step.SubStepAt(i))

		nextNodes = append(nextNodes, *nextNode)
	}
	return &armotypes.AttackChainNode{
		Name:             step.GetName(),
		Description:      step.GetDescription(),
		ControlIDs:       controlIDs,
		Vulnerabilities:  imageVulnerabilities,           // Update this with your actual logic
		RelatedResources: []armotypes.PortalDesignator{}, // Enrich from PostureReportResultRaw new "RelatedResources" field.
		NextNodes:        nextNodes,
	}
}

// GenerateAttackChainID generates attackChainID
// structure: attackTrackName/cluster/apiVersion/namespace/kind/name
func GenerateAttackChainID(attackTrack v1alpha1.IAttackTrack, postureResourceSummary *armotypes.PostureResourceSummary) string {
	attributes := postureResourceSummary.Designators.Attributes
	elements := []string{attackTrack.GetName(), attributes["cluster"], attributes["apiVersion"], attributes["namespace"], attributes["kind"], attributes["name"]}
	return strings.Join(elements, "/")
}
