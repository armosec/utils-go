package attackchains

import (
	"strings"
	"time"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	cscanlib "github.com/armosec/armoapi-go/containerscan"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/str"
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

// convertVulToControl - convert vulnerability to control object. This is done in order to unify the way we handle vulnarabilities and controls when generating the attack chains.
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
				"controlTypeTags":                    tags,
				"attackTracks":                       attackTrackCategories,
				"vulnerabilities":                    vul.Vulnerabilities,
				identifiers.AttributeContainerScanId: vul.ContainerScanID,
				identifiers.AttributeContainerName:   vul.ContainerName,
			},
		},
	}
}

// isVulnerableRelevantToAttackChain checks if the vulnerability is relevant to the attack chain
func isVulnerableRelevantToAttackChain(vul *cscanlib.CommonContainerScanSummaryResult) bool {
	// validate relevancy
	if !vul.HasRelevancyData || (vul.HasRelevancyData && vul.RelevantLabel == "yes") {
		//validate severity
		if vul.Severity == "Critical" {
			return true
		}
		for _, stat := range vul.SeveritiesStats {
			if stat.Severity == "Critical" && stat.TotalCount > 0 {
				return true
			}
		}
	}
	return false
}

// validateWorkLoadMatch checks if the vulnerability and the posture resource summary are of the same workload
func validateWorkLoadMatch(postureResourceSummary *armotypes.PostureResourceSummary, vul *cscanlib.CommonContainerScanSummaryResult) bool {
	prsAttributes := postureResourceSummary.Designators.Attributes
	vulAttributes := vul.Designators.Attributes
	// check that all these fields match:
	// cluster, namespace, kind, name
	// check is case insensitive
	if strings.ToLower(prsAttributes["kind"]) == strings.ToLower(vulAttributes["kind"]) &&
		strings.ToLower(prsAttributes["name"]) == strings.ToLower(vulAttributes["name"]) &&
		strings.ToLower(prsAttributes["namespace"]) == strings.ToLower(vulAttributes["namespace"]) &&
		strings.ToLower(prsAttributes["cluster"]) == strings.ToLower(vulAttributes["cluster"]) {
		return true
	}
	return false
}

func ConvertAttackTracksToAttackChains(attacktracks []v1alpha1.IAttackTrack, attributes map[string]string, resourceID, reportID string) []*armotypes.AttackChain {
	var attackChains []*armotypes.AttackChain
	for _, attackTrack := range attacktracks {
		attackChains = append(attackChains, ConvertAttackTrackToAttackChain(attackTrack, attributes, resourceID, reportID))
	}
	return attackChains

}

func ConvertAttackTrackToAttackChain(attackTrack v1alpha1.IAttackTrack, attributes map[string]string, resourceID, reportID string) *armotypes.AttackChain {
	var chainNodes = ConvertAttackTrackStepToAttackChainNode(attackTrack.GetData())
	return &armotypes.AttackChain{
		AttackChainNodes: *chainNodes,
		AttackChainConfig: armotypes.AttackChainConfig{
			Description: attackTrack.GetDescription(),
			PortalBase: armotypes.PortalBase{
				Name: attackTrack.GetName(),
			},
			ClusterName:      attributes[identifiers.AttributeCluster],
			Resource:         GenerateAttackChainResource(attributes, resourceID),
			AttackChainID:    GenerateAttackChainID(attackTrack, attributes),
			CustomerGUID:     attributes[identifiers.AttributeCustomerGUID],
			UIStatus:         &armotypes.AttackChainUIStatus{FirstSeen: time.Now().String()},
			LatestReportGUID: reportID,
		},
	}
}

func GenerateAttackChainResource(attributes map[string]string, resourceID string) identifiers.PortalDesignator {
	attributes[identifiers.AttributeResourceID] = resourceID
	return identifiers.PortalDesignator{DesignatorType: identifiers.DesignatorAttributes, Attributes: attributes}
}

func ConvertAttackTrackStepToAttackChainNode(step v1alpha1.IAttackTrackStep) *armotypes.AttackChainNode {
	var controlIDs []string
	var imageVulnerabilities []armotypes.Vulnerabilities

	if step.GetName() == "" {
		return nil
	}

	if step.DoesCheckVulnerabilities() {
		for _, vulControl := range step.GetControls() {
			containerScanID := vulControl.(*reporthandling.Control).Attributes[identifiers.AttributeContainerScanId].(string)
			containerName := vulControl.(*reporthandling.Control).Attributes[identifiers.AttributeContainerName].(string)
			vulnerabilities := vulControl.(*reporthandling.Control).Attributes["vulnerabilities"].([]cscanlib.ShortVulnerabilityResult)

			vulNames := []string{}

			if len(vulnerabilities) > 0 {
				for _, vul := range vulnerabilities {
					vulNames = append(vulNames, vul.Name)
				}
			}

			imageVulnerabilities = append(imageVulnerabilities, armotypes.Vulnerabilities{ContainersScanID: containerScanID, ContainerName: containerName, Names: vulNames})

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
		Vulnerabilities:  imageVulnerabilities,
		RelatedResources: []identifiers.PortalDesignator{}, // Enrich from PostureReportResultRaw new "RelatedResources" field.
		NextNodes:        nextNodes,
	}
}

// GenerateAttackChainID generates attackChainID
// structure: attackTrackName/cluster/apiVersion/namespace/kind/name
func GenerateAttackChainID(attackTrack v1alpha1.IAttackTrack, attributes map[string]string) string {
	elements := []string{attackTrack.GetName(), attributes["cluster"], attributes["namespace"], attributes["kind"], attributes["name"]}
	return str.AsFNVHash(strings.Join(elements, "/"))
}
