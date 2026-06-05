# METADATA
# title: ECR repository must not grant public access
# description: A repository resource policy that grants Allow to Principal "*" exposes images to the public internet. Repositories without any policy are private by default and pass this check.
# custom:
#   controls:
#     - ctrl-cc6-8-005
#     - ctrl-cc6-8-013
#     - ctrl-cc8-1-014
#     - ctrl-cc8-1-015
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_deny_public_access

import future.keywords.in

# Fail if the policy text cannot be parsed (fail-closed when has_repository_policy is true).
violation[{"id": "public_access_granted", "parse_error": "repository_policy_text could not be parsed as JSON"}] if {
	input.resource_type == "ecr-repository"
	input.has_repository_policy
	not json.unmarshal(input.repository_policy_text)
}

violation[{"id": "public_access_granted"}] if {
	input.resource_type == "ecr-repository"
	input.has_repository_policy
	policy := json.unmarshal(input.repository_policy_text)
	policy != null
	some statement in statements(policy)
	statement.Effect == "Allow"
	is_wildcard_principal(statement.Principal)
}

# statements normalises Statement to an array whether it is already an array or a single object.
statements(policy) := policy.Statement if {
	is_array(policy.Statement)
}

statements(policy) := [policy.Statement] if {
	not is_array(policy.Statement)
	policy.Statement != null
}

is_wildcard_principal(p) if p == "*"

is_wildcard_principal(p) if p.AWS == "*"

is_wildcard_principal(p) if {
	some v in p.AWS
	v == "*"
}

title := "ECR repository must not grant public access"
description := "A repository resource policy that grants Allow to Principal \"*\" exposes images to the public internet. Repositories without any policy are private by default and pass this check."

risk_templates := [{
	"name":            "public_access_granted",
	"title":           "ECR repository grants public access",
	"statement":       "A wildcard Allow principal in the repository resource policy exposes container images to the public internet, allowing unauthenticated pull access to proprietary or sensitive image contents.",
	"likelihood_hint": "critical",
	"impact_hint":     "critical",
	"violation_ids":   ["public_access_granted"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title":       "Improper Access Control",
			"url":         "https://cwe.mitre.org/data/definitions/284.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-668",
			"title":       "Exposure of Resource to Wrong Sphere",
			"url":         "https://cwe.mitre.org/data/definitions/668.html"
		}
	],
	"remediation": {
		"title":       "Remove public wildcard principals from the repository resource policy",
		"description": "Edit the repository resource policy to remove or replace any statement that grants Allow access to Principal \"*\", and restrict cross-account access to specific, named AWS principals.",
		"tasks": [
			{"title": "Identify all statements in the repository policy with Effect=Allow and Principal set to a wildcard"},
			{"title": "Replace wildcard principals with the specific AWS account IDs or IAM ARNs that require pull access"},
			{"title": "Confirm no legitimate workload depends on anonymous public access before removing the wildcard"},
			{"title": "If public distribution is required, migrate the repository to ECR Public rather than using a resource policy wildcard on a private repository"}
		]
	}
}]
