package policy

type ScopedCredentialPolicyChecklistResult struct {
	SchemaVersion                    string                                `json:"schema_version"`
	Status                           string                                `json:"status"`
	Scope                            string                                `json:"scope"`
	CheckCount                       int                                   `json:"check_count"`
	Checks                           []ScopedCredentialPolicyChecklistItem `json:"checks"`
	CredentialValueInspectionAllowed bool                                  `json:"credential_value_inspection_allowed"`
	CredentialValuesInspected        bool                                  `json:"credential_values_inspected"`
	CredentialValuesStored           bool                                  `json:"credential_values_stored"`
	RequiresCredentialMaterial       bool                                  `json:"requires_credential_material"`
	SafeToExecute                    bool                                  `json:"safe_to_execute"`
	ExecutesWork                     bool                                  `json:"executes_work"`
	ApprovesWork                     bool                                  `json:"approves_work"`
	MutatesRepositories              bool                                  `json:"mutates_repositories"`
	ProviderCallsAllowed             bool                                  `json:"provider_calls_allowed"`
	ReleaseOrPublishAllowed          bool                                  `json:"release_or_publish_allowed"`
	ClaimsAuthorityAdvance           bool                                  `json:"claims_authority_advance"`
	RSIRemainsDenied                 bool                                  `json:"rsi_remains_denied"`
}

type ScopedCredentialPolicyChecklistItem struct {
	ID                      string `json:"id"`
	Status                  string `json:"status"`
	Requirement             string `json:"requirement"`
	Evidence                string `json:"evidence"`
	RequiresCredentialValue bool   `json:"requires_credential_value"`
	AllowsCredentialCapture bool   `json:"allows_credential_capture"`
}

func ScopedCredentialPolicyChecklist(schemaVersion string) ScopedCredentialPolicyChecklistResult {
	checks := []ScopedCredentialPolicyChecklistItem{
		{
			ID:                      "credential-purpose-declared",
			Status:                  "passed",
			Requirement:             "Every credential-dependent action names its purpose and owning component before execution.",
			Evidence:                "metadata-only checklist row; no credential value is read",
			RequiresCredentialValue: false,
			AllowsCredentialCapture: false,
		},
		{
			ID:                      "credential-scope-minimal",
			Status:                  "passed",
			Requirement:             "Credential use must be scoped to the minimum operation and repository boundary.",
			Evidence:                "operator-readback requirement only; no token, key, or secret material is requested",
			RequiresCredentialValue: false,
			AllowsCredentialCapture: false,
		},
		{
			ID:                      "credential-source-external",
			Status:                  "passed",
			Requirement:             "Credential material remains in the operator-controlled provider or host environment.",
			Evidence:                "Covenant records presence/absence intent only and does not copy credential bytes",
			RequiresCredentialValue: false,
			AllowsCredentialCapture: false,
		},
		{
			ID:                      "credential-redaction-required",
			Status:                  "passed",
			Requirement:             "Evidence, errors, and public reports must redact credential-like values.",
			Evidence:                "public-safety scan and schema-backed report fields are metadata-only",
			RequiresCredentialValue: false,
			AllowsCredentialCapture: false,
		},
		{
			ID:                      "credential-no-provider-call",
			Status:                  "passed",
			Requirement:             "This checklist does not perform provider calls or credential validation probes.",
			Evidence:                "provider_calls_allowed=false and safe_to_execute=false",
			RequiresCredentialValue: false,
			AllowsCredentialCapture: false,
		},
	}
	return ScopedCredentialPolicyChecklistResult{
		SchemaVersion:                    schemaVersion,
		Status:                           "ready",
		Scope:                            "metadata_and_operator_checklist_only",
		CheckCount:                       len(checks),
		Checks:                           checks,
		CredentialValueInspectionAllowed: false,
		CredentialValuesInspected:        false,
		CredentialValuesStored:           false,
		RequiresCredentialMaterial:       false,
		SafeToExecute:                    false,
		ExecutesWork:                     false,
		ApprovesWork:                     false,
		MutatesRepositories:              false,
		ProviderCallsAllowed:             false,
		ReleaseOrPublishAllowed:          false,
		ClaimsAuthorityAdvance:           false,
		RSIRemainsDenied:                 true,
	}
}
