package closure

func Evaluate(input Input) Matrix {
	rows := make([]Row, 0, len(input.Obligations))
	status := StatusAccepted
	for _, obligation := range input.Obligations {
		row := evaluateObligation(input, obligation.ID, obligation.Required)
		if obligation.Required && row.Status != RowStatusClosed {
			status = StatusRejected
		}
		rows = append(rows, row)
	}
	if input.RunStatus != "success" {
		status = StatusRejected
	}
	return Matrix{
		SchemaVersion:  MatrixSchemaVersion,
		RunID:          input.RunID,
		ContractDigest: input.ContractDigest,
		Status:         status,
		Rows:           rows,
	}
}

func evaluateObligation(input Input, obligationID string, required bool) Row {
	taskIDs := claimingTaskIDs(input, obligationID)
	artifactIDs := artifactIDsForTasks(input, taskIDs)
	policyDecisionIDs := policyDecisionIDsForTasks(input, taskIDs)
	closed := input.RunStatus == "success" && hasSuccessfulTask(input, taskIDs)
	status := RowStatusOpen
	reason := "no successful task claimed obligation"
	if input.RunStatus != "success" {
		reason = "run did not finish successfully"
	} else if closed {
		status = RowStatusClosed
		reason = "closed by successful task evidence"
	}
	return Row{
		ObligationID:      obligationID,
		Required:          required,
		Status:            status,
		TaskIDs:           taskIDs,
		ArtifactIDs:       artifactIDs,
		PolicyDecisionIDs: policyDecisionIDs,
		Reason:            reason,
	}
}

func claimingTaskIDs(input Input, obligationID string) []string {
	taskIDs := []string{}
	for _, task := range input.Tasks {
		for _, taskObligationID := range task.Obligations {
			if taskObligationID == obligationID {
				taskIDs = append(taskIDs, task.ID)
				break
			}
		}
	}
	return taskIDs
}

func artifactIDsForTasks(input Input, taskIDs []string) []string {
	artifactIDs := []string{}
	for _, taskID := range taskIDs {
		artifactIDs = append(artifactIDs, input.TaskArtifacts[taskID]...)
	}
	return artifactIDs
}

func policyDecisionIDsForTasks(input Input, taskIDs []string) []string {
	taskSet := map[string]bool{}
	for _, taskID := range taskIDs {
		taskSet[taskID] = true
	}
	decisionIDs := []string{}
	for _, decision := range input.PolicyDecisions {
		if taskSet[decision.TaskID] {
			decisionIDs = append(decisionIDs, decision.DecisionID)
		}
	}
	return decisionIDs
}

func hasSuccessfulTask(input Input, taskIDs []string) bool {
	for _, taskID := range taskIDs {
		if input.TaskStatuses[taskID] == "success" {
			return true
		}
	}
	return false
}
