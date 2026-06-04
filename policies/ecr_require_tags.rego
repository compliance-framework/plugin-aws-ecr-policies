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
	"name":            "missing_or_incorrect_required_tags",
	"title":           "ECR repository has missing or incorrect required tags",
	"statement":       "One or more required tags are absent or carry an incorrect value, preventing cost attribution, ownership tracing, and lifecycle management of the repository. Untagged resources cannot be automatically governed by tag-based access control policies or cost allocation rules.",
	"likelihood_hint": "low",
	"impact_hint":     "low",
	"violation_ids":   ["missing_or_incorrect_required_tags"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title":       "Improper Access Control",
			"url":         "https://cwe.mitre.org/data/definitions/284.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title":       "Incomplete Documentation",
			"url":         "https://cwe.mitre.org/data/definitions/1059.html"
		}
	],
	"remediation": {
		"title":       "Apply all required tags with correct values to the ECR repository",
		"description": "Add any missing tags and correct any tag values that do not match policy requirements so the repository can be attributed to the correct owner, cost centre, and environment.",
		"tasks": [
			{"title": "Review the required tag keys defined in data.required_repository_tags and the expected values in data.required_tag_values"},
			{"title": "Add the missing tags to the repository via the AWS Console, CLI, or infrastructure-as-code"},
			{"title": "Correct any existing tag values that do not match the required values"},
			{"title": "Enforce tagging at creation time using AWS Tag Policies or IaC pre-deployment checks to prevent recurrence"}
		]
	}
}]
