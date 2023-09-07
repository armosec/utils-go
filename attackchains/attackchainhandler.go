package attackchains

import (
	"fmt"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	cscanlib "github.com/armosec/armoapi-go/containerscan"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

const (
	securityFrameworkName = "security"
)

type AttackChainsEngine struct {
	attackTracks           []v1alpha1.IAttackTrack            // All attack tracks
	allAttackTrackControls map[string]*reporthandling.Control // All controls that might potentially be relevant to any of the attack tracks
}

func NewAttackChainHandler(attackTracks []v1alpha1.IAttackTrack, allAttackTrackControls map[string]*reporthandling.Control) (*AttackChainsEngine, error) {

	if len(attackTracks) == 0 {
		return nil, fmt.Errorf("expected to find at least one attack track")
	}

	for _, attackTrack := range attackTracks {
		if !attackTrack.IsValid() {
			return nil, fmt.Errorf("invalid attack track: %s", attackTrack.GetName())
		}
	}

	handler := &AttackChainsEngine{
		attackTracks:           attackTracks,
		allAttackTrackControls: allAttackTrackControls,
	}

	return handler, nil
}

// detectSingleAttackTrack - detect attach chains out of a single attack track
func (h *AttackChainsEngine) detectSingleAttackChain(attackTrack v1alpha1.IAttackTrack, controlsLookup v1alpha1.AttackTrackControlsLookup) (v1alpha1.IAttackTrack, error) {

	if attackTrack == nil {
		return nil, fmt.Errorf("attackTrack is nil")
	}

	if controlsLookup == nil {
		return nil, fmt.Errorf("controlsLookup is nil")
	}

	if !controlsLookup.HasAssociatedControls(attackTrack.GetName()) {
		return nil, nil
	}

	// Load the failed controls into the attack track
	allPathsHandler := v1alpha1.NewAttackTrackAllPathsHandler(attackTrack, &controlsLookup)

	// Calculate all the paths for the attack track
	// nbeed to take the first item in the list.
	paths := allPathsHandler.CalculatePathsRootToLeaf()
	if len(paths) == 0 {
		return nil, nil
	}
	return allPathsHandler.GenerateAttackTrackFromPaths(paths), nil

}

// getAttackTrackControlsLookup returns a lookup of all the controls that are relevant to the attack tracks
func (h *AttackChainsEngine) getAttackTrackControlsLookup(postureResourceSummary *armotypes.PostureResourceSummary, vuls []*cscanlib.CommonContainerScanSummaryResult) (v1alpha1.AttackTrackControlsLookup, error) {

	relevantControls, err := h.getRelevantControls(postureResourceSummary)
	if err != nil {
		return nil, err
	}

	if len(relevantControls) == 0 {
		return nil, nil
	}

	attackTracks, err := h.GetAttackTrack()
	if err != nil {
		return nil, err
	}

	vulRelevants := make([]*cscanlib.CommonContainerScanSummaryResult, 0, len(vuls))

	for _, vul := range vuls {
		if isVulnerableRelevantToAttackChain(vul) {
			vulRelevants = append(vulRelevants, vul)

			// Convert the vulnarable image to a control structure
			volAsControl := convertVulToControl(vul, []string{securityFrameworkName}, attackTracks)
			if volAsControl != nil {
				relevantControls[volAsControl.ControlID] = volAsControl
			}
		}
	}

	relevantControlsIDs := make([]string, 0, len(relevantControls))

	for _, control := range relevantControls {
		relevantControlsIDs = append(relevantControlsIDs, control.GetControlId())
	}

	controlsLookup := v1alpha1.NewAttackTrackControlsLookup(attackTracks, relevantControlsIDs, relevantControls)

	return controlsLookup, nil

}

// DetectAllAttackChains - Detects all the attack chains that are relevant to the postureResourceSummary
func (h *AttackChainsEngine) DetectAllAttackChains(postureResourceSummary *armotypes.PostureResourceSummary, vul []*cscanlib.CommonContainerScanSummaryResult) ([]v1alpha1.IAttackTrack, error) {

	attackChains := []v1alpha1.IAttackTrack{}

	// If the postureResourceSummary is not relevant to any attack track, return nil
	if !isSupportedKind(postureResourceSummary.Designators.Attributes["kind"]) {
		return nil, nil
	}

	// Get all the attack tracks, return error if failed
	attackTracks, err := h.GetAttackTrack()
	if err != nil {
		return nil, err
	}

	// Get controls lookup, return error if failed
	controlsLookup, err := h.getAttackTrackControlsLookup(postureResourceSummary, vul)
	if err != nil {
		return nil, err
	}

	if controlsLookup == nil {
		return nil, nil
	}

	// For each attack track, detect attack chains.
	for _, attackTrack := range attackTracks {
		calculatedAttackChain, err := h.detectSingleAttackChain(attackTrack, controlsLookup)
		if err != nil {
			return nil, err
		}

		if calculatedAttackChain != nil {
			attackChains = append(attackChains, calculatedAttackChain)
		}

	}

	return attackChains, nil

}

// GetAttackTrack - Returns all the attack tracks
func (h *AttackChainsEngine) GetAttackTrack() ([]v1alpha1.IAttackTrack, error) {
	if len(h.attackTracks) == 0 {
		return nil, fmt.Errorf("attack tracks not found")
	}
	return h.attackTracks, nil
}

// getRelevantControls - Returns all the controls that are relevant to the postureResourceSummary
// The relevant controls are the failed controls and the warning controls
func (h *AttackChainsEngine) getRelevantControls(postureResourceSummary *armotypes.PostureResourceSummary) (map[string]v1alpha1.IAttackTrackControl, error) {

	n_relevant := len(postureResourceSummary.FailedControl) + len(postureResourceSummary.WarningControls)
	relevantControlsIDs := append(postureResourceSummary.FailedControl, postureResourceSummary.WarningControls...)

	relevantControls := make(map[string]v1alpha1.IAttackTrackControl, n_relevant)

	for _, controlID := range relevantControlsIDs {
		control, ok := h.allAttackTrackControls[controlID]
		if ok {
			relevantControls[controlID] = control
		}
	}

	return relevantControls, nil
}
