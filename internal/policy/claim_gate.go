package policy

const (
	ClaimPublishGateSchemaVersion = "covenant.rsi-claim-publish-gate.v1"
	fullRSIClaimPublishResource   = "full-autonomous-self-mutating-rsi"
)

type ClaimPublishGateInput struct {
	ClaimReadiness map[string]any
	ReadbackIndex  map[string]any
}

type ClaimPublishGateResult struct {
	SchemaVersion        string                           `json:"schema_version"`
	ClaimLevel           string                           `json:"claim_level"`
	ClaimPublishResource string                           `json:"claim_publish_resource"`
	Status               string                           `json:"status"`
	Decision             string                           `json:"decision"`
	PublishAuthority     bool                             `json:"publish_authority"`
	Reason               string                           `json:"reason"`
	BlockerCount         int                              `json:"blocker_count"`
	Blockers             []ClaimPublishGateBlocker        `json:"blockers"`
	ObservedEvidence     ClaimPublishGateObservedEvidence `json:"observed_evidence"`
	TrustBoundary        ClaimPublishGateTrustBoundary    `json:"trust_boundary"`
}

type ClaimPublishGateBlocker struct {
	ID               string `json:"id"`
	EvidenceState    string `json:"evidence_state"`
	RequiredEvidence string `json:"required_evidence"`
}

type ClaimPublishGateObservedEvidence struct {
	ClaimReadiness              ClaimReadinessObservation              `json:"claim_readiness"`
	LiveSelfChangeReadbackIndex LiveSelfChangeReadbackIndexObservation `json:"live_self_change_readback_index"`
}

type ClaimReadinessObservation struct {
	SchemaVersion        string `json:"schema_version,omitempty"`
	Status               string `json:"status,omitempty"`
	FullClaimDecision    string `json:"full_claim_decision,omitempty"`
	ClaimPublishApproved bool   `json:"claim_publish_approved"`
}

type LiveSelfChangeReadbackIndexObservation struct {
	SchemaVersion                    string `json:"schema_version,omitempty"`
	Status                           string `json:"status,omitempty"`
	ControlPlaneReadbackStatus       string `json:"control_plane_readback_status,omitempty"`
	RetainedClaimLevelEvidenceStatus string `json:"retained_claim_level_evidence_status,omitempty"`
	FullClaimBoundaryDecision        string `json:"full_claim_boundary_decision,omitempty"`
}

type ClaimPublishGateTrustBoundary struct {
	LocalOnly           bool `json:"local_only"`
	UsesNetwork         bool `json:"uses_network"`
	MutatesRepositories bool `json:"mutates_repositories"`
	PublishesClaims     bool `json:"publishes_claims"`
	ApprovesRSIClaims   bool `json:"approves_rsi_claims"`
	StoresCredentials   bool `json:"stores_credentials"`
}

func EvaluateRSIClaimPublishGate(input ClaimPublishGateInput) ClaimPublishGateResult {
	fullClaim := nestedMap(input.ClaimReadiness, "claims", ClaimLevelFullAutonomousSelfMutatingRSI)
	partialReadback := nestedMap(fullClaim, "partial_evidence", "live_self_change_readback_index")
	readbackSource := nestedMap(input.ReadbackIndex, "sources", "control_plane_readback")
	retained := nestedMap(input.ReadbackIndex, "retained_claim_level_evidence")
	fullBoundary := nestedMap(input.ReadbackIndex, "full_claim_boundary")

	observed := ClaimPublishGateObservedEvidence{
		ClaimReadiness: ClaimReadinessObservation{
			SchemaVersion:        stringField(input.ClaimReadiness, "schema_version"),
			Status:               stringField(input.ClaimReadiness, "status"),
			FullClaimDecision:    stringField(fullClaim, "decision"),
			ClaimPublishApproved: boolField(partialReadback, "claim_publish_approved"),
		},
		LiveSelfChangeReadbackIndex: LiveSelfChangeReadbackIndexObservation{
			SchemaVersion:                    stringField(input.ReadbackIndex, "schema_version"),
			Status:                           stringField(input.ReadbackIndex, "status"),
			ControlPlaneReadbackStatus:       stringField(readbackSource, "status"),
			RetainedClaimLevelEvidenceStatus: stringField(retained, "status"),
			FullClaimBoundaryDecision:        stringField(fullBoundary, "decision"),
		},
	}

	blockers := claimReadinessBlockers(fullClaim)
	for _, id := range stringSliceField(fullBoundary, "remaining_blockers") {
		blockers = appendBlockerIfMissing(blockers, blockerForID(id))
	}
	if observed.LiveSelfChangeReadbackIndex.Status != "passed" {
		blockers = appendBlockerIfMissing(blockers, ClaimPublishGateBlocker{
			ID:               "readback_index_not_passed",
			EvidenceState:    "missing",
			RequiredEvidence: "AO2 live self-change readback evidence index must pass",
		})
	}
	if observed.LiveSelfChangeReadbackIndex.ControlPlaneReadbackStatus != "passed" {
		blockers = appendBlockerIfMissing(blockers, ClaimPublishGateBlocker{
			ID:               "control_plane_readback_not_passed",
			EvidenceState:    "missing",
			RequiredEvidence: "ao2-control-plane readback must pass before claim publication",
		})
	}
	if observed.LiveSelfChangeReadbackIndex.RetainedClaimLevelEvidenceStatus != "present" {
		blockers = appendBlockerIfMissing(blockers, ClaimPublishGateBlocker{
			ID:               "retained_claim_level_evidence_missing",
			EvidenceState:    "missing",
			RequiredEvidence: "retained claim-level readback evidence must be present",
		})
	}
	if !observed.ClaimReadiness.ClaimPublishApproved {
		blockers = appendBlockerIfMissing(blockers, blockerForID("covenant_claim_publish_approval"))
	}

	publishAuthority := observed.ClaimReadiness.ClaimPublishApproved &&
		observed.ClaimReadiness.FullClaimDecision == "allowed" &&
		observed.LiveSelfChangeReadbackIndex.Status == "passed" &&
		observed.LiveSelfChangeReadbackIndex.FullClaimBoundaryDecision != "denied" &&
		len(blockers) == 0

	status := "denied"
	decision := DecisionDeny
	reason := "full autonomous self-mutating RSI claim publication denied; retained readback evidence is not claim-publish authority"
	if publishAuthority {
		status = "approved"
		decision = DecisionAllow
		reason = "full autonomous self-mutating RSI claim publication approved by Covenant evidence gate"
	}

	return ClaimPublishGateResult{
		SchemaVersion:        ClaimPublishGateSchemaVersion,
		ClaimLevel:           ClaimLevelFullAutonomousSelfMutatingRSI,
		ClaimPublishResource: fullRSIClaimPublishResource,
		Status:               status,
		Decision:             decision,
		PublishAuthority:     publishAuthority,
		Reason:               reason,
		BlockerCount:         len(blockers),
		Blockers:             blockers,
		ObservedEvidence:     observed,
		TrustBoundary: ClaimPublishGateTrustBoundary{
			LocalOnly:           true,
			UsesNetwork:         false,
			MutatesRepositories: false,
			PublishesClaims:     false,
			ApprovesRSIClaims:   false,
			StoresCredentials:   false,
		},
	}
}

func claimReadinessBlockers(fullClaim map[string]any) []ClaimPublishGateBlocker {
	raw, ok := fullClaim["blockers"].([]any)
	if !ok {
		return nil
	}
	blockers := make([]ClaimPublishGateBlocker, 0, len(raw))
	for _, entry := range raw {
		blockerMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		blocker := ClaimPublishGateBlocker{
			ID:               stringField(blockerMap, "id"),
			EvidenceState:    stringField(blockerMap, "evidence_state"),
			RequiredEvidence: stringField(blockerMap, "required_evidence"),
		}
		if blocker.ID == "" {
			continue
		}
		if blocker.EvidenceState == "" {
			blocker.EvidenceState = "missing"
		}
		if blocker.RequiredEvidence == "" {
			blocker.RequiredEvidence = "claim-publish blocker remains unresolved"
		}
		blockers = appendBlockerIfMissing(blockers, blocker)
	}
	return blockers
}

func blockerForID(id string) ClaimPublishGateBlocker {
	switch id {
	case "covenant_claim_publish_approval":
		return ClaimPublishGateBlocker{
			ID:               id,
			EvidenceState:    "missing",
			RequiredEvidence: "Covenant approval to publish the full autonomous self-mutating RSI claim",
		}
	case "rehearsal_not_claim_publish_evidence":
		return ClaimPublishGateBlocker{
			ID:               id,
			EvidenceState:    "blocking",
			RequiredEvidence: "live rehearsal and readback evidence must not be treated as claim-publish authority",
		}
	default:
		return ClaimPublishGateBlocker{
			ID:               id,
			EvidenceState:    "blocking",
			RequiredEvidence: "claim-publish blocker remains unresolved",
		}
	}
}

func appendBlockerIfMissing(blockers []ClaimPublishGateBlocker, blocker ClaimPublishGateBlocker) []ClaimPublishGateBlocker {
	if blocker.ID == "" {
		return blockers
	}
	for _, existing := range blockers {
		if existing.ID == blocker.ID {
			return blockers
		}
	}
	return append(blockers, blocker)
}

func nestedMap(root map[string]any, keys ...string) map[string]any {
	current := root
	for _, key := range keys {
		if current == nil {
			return nil
		}
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

func stringField(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}

func boolField(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	value, _ := values[key].(bool)
	return value
}

func stringSliceField(values map[string]any, key string) []string {
	if values == nil {
		return nil
	}
	raw, ok := values[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		item, ok := value.(string)
		if ok && item != "" {
			result = append(result, item)
		}
	}
	return result
}
