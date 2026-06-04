# METADATA
# title: ECR repository must enforce image tag immutability
# description: Mutable image tags allow silent overwriting of production references without detection. Immutable tags prevent unauthorised substitution and support deployment validation.
# custom:
#   controls:
#     - ctrl-cc6-8-002
#     - ctrl-cc6-8-005
#     - ctrl-cc6-8-007
#     - ctrl-cc8-1-001
#     - ctrl-cc8-1-008
#     - ctrl-cc8-1-014
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_tag_immutability

violation[{}] if {
	input.resource_type == "ecr-repository"
	not input.image_tag_immutability == "IMMUTABLE"
}

title := "ECR repository must enforce image tag immutability"
description := "Mutable image tags allow silent overwriting of production references without detection. Immutable tags prevent unauthorised substitution and support deployment validation."

risk_templates := [{
	"name":            "image_tags_mutable",
	"title":           "ECR image tags are mutable",
	"statement":       "Mutable image tags allow silent overwriting of production references, enabling undetected substitution of container images without triggering deployment controls.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["image_tags_mutable"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-345",
			"title":       "Insufficient Verification of Data Authenticity",
			"url":         "https://cwe.mitre.org/data/definitions/345.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-494",
			"title":       "Download of Code Without Integrity Check",
			"url":         "https://cwe.mitre.org/data/definitions/494.html"
		}
	],
	"remediation": {
		"title":       "Enable IMMUTABLE tag setting on the ECR repository",
		"description": "Set the repository tag immutability to IMMUTABLE so that once a tag is pushed it cannot be overwritten, ensuring deployments always reference the exact image that was tested.",
		"tasks": [
			{"title": "Update the repository tag immutability setting to IMMUTABLE in the AWS Console or via CLI/IaC"},
			{"title": "Audit existing image references in CI/CD pipelines to confirm they use versioned or digest-based tags rather than mutable aliases such as 'latest'"},
			{"title": "Retag any ambiguously named images with immutable version identifiers"},
			{"title": "Verify the change persists in infrastructure-as-code and is enforced by pipeline policy"}
		]
	}
}]
