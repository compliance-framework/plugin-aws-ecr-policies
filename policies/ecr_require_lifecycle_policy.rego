# METADATA
# title: ECR repository must have a lifecycle policy configured
# description: Repositories without lifecycle policies accumulate stale images indefinitely, violating asset disposal requirements. A lifecycle policy proves a defined disposal mechanism exists.
# custom:
#   controls:
#     - ctrl-cc6-5-001
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_lifecycle_policy

violation[{}] if {
	input.resource_type == "ecr-repository"
	not input.has_lifecycle_policy
}

title := "ECR repository must have a lifecycle policy configured"
description := "Repositories without lifecycle policies accumulate stale images indefinitely, violating asset disposal requirements. A lifecycle policy proves a defined disposal mechanism exists."

risk_templates := [{
	"name":             "lifecycle_policy_missing",
	"title":            "ECR repository has no lifecycle policy",
	"statement":        "Without a lifecycle policy, stale and superseded images accumulate indefinitely, increasing storage cost and attack surface.",
	"likelihood_hint":  "low",
	"impact_hint":      "medium",
	"violation_ids":    ["lifecycle_policy_missing"],
}]
