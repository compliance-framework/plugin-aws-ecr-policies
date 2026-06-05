# METADATA
# title: ECR repository must have a lifecycle policy configured
# description: Repositories without lifecycle policies accumulate stale images indefinitely, violating asset disposal requirements. A lifecycle policy proves a defined disposal mechanism exists.
# custom:
#   controls:
#     - ctrl-cc6-5-001
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_lifecycle_policy

violation[{"id": "lifecycle_policy_missing"}] if {
	input.resource_type == "ecr-repository"
	not input.has_lifecycle_policy
}

title := "ECR repository must have a lifecycle policy configured"
description := "Repositories without lifecycle policies accumulate stale images indefinitely, violating asset disposal requirements. A lifecycle policy proves a defined disposal mechanism exists."

risk_templates := [{
	"name":            "lifecycle_policy_missing",
	"title":           "ECR repository has no lifecycle policy",
	"statement":       "Without a lifecycle policy, stale and superseded images accumulate indefinitely, increasing storage cost, expanding the exploitable image surface, and violating asset disposal requirements.",
	"likelihood_hint": "low",
	"impact_hint":     "medium",
	"violation_ids":   ["lifecycle_policy_missing"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-459",
			"title":       "Incomplete Cleanup",
			"url":         "https://cwe.mitre.org/data/definitions/459.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-404",
			"title":       "Improper Resource Shutdown or Release",
			"url":         "https://cwe.mitre.org/data/definitions/404.html"
		}
	],
	"remediation": {
		"title":       "Add a lifecycle policy to the ECR repository",
		"description": "Define lifecycle rules that expire untagged images and limit the number of retained tagged images to ensure stale artefacts are disposed of in accordance with policy.",
		"tasks": [
			{"title": "Create a lifecycle policy that expires untagged images after a defined number of days"},
			{"title": "Add rules to retain only a limited count of tagged images per naming prefix"},
			{"title": "Test the lifecycle policy using the ECR dry-run API against the non-production repository before applying broadly"},
			{"title": "Encode the lifecycle policy in infrastructure-as-code so it is applied automatically on repository creation"}
		]
	}
}]
