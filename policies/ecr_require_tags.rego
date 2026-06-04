# METADATA
# title: ECR repository must carry all required tags
# description: Missing required tags prevent cost attribution, ownership tracing, and lifecycle management of container repositories.
# custom:
#   controls:
#     - CC6.1
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_tags

import future.keywords.in

violation[{"missing_tag": tag}] if {
	input.resource_type == "ecr-repository"
	some tag in data.required_repository_tags
	not input.tags[tag]
}

violation[{"invalid_tag_value": tag, "expected": expected, "got": got}] if {
	input.resource_type == "ecr-repository"
	some tag, expected in data.required_tag_values
	got := input.tags[tag]  # only binds when the tag is present; missing tags fall through to missing_tag
	got != expected
}

title := "ECR repository must carry all required tags"
description := "Missing required tags prevent cost attribution, ownership tracing, and lifecycle management of container repositories."

risk_templates := [{
	"name":             "missing_or_incorrect_required_tags",
	"title":            "ECR repository has missing or incorrect required tags",
	"statement":        "One or more required tags are absent or carry an incorrect value, preventing cost attribution, ownership tracing, and lifecycle management of the repository.",
	"likelihood_hint":  "low",
	"impact_hint":      "low",
	"violation_ids":    ["missing_or_incorrect_required_tags"],
}]
