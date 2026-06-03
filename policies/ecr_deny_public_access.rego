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

violation[{}] if {
	input.resource_type == "ecr-repository"
	input.has_repository_policy
	policy := json.unmarshal(input.repository_policy_text)
	some statement in policy.Statement
	statement.Effect == "Allow"
	is_wildcard_principal(statement.Principal)
}

is_wildcard_principal(p) if p == "*"

is_wildcard_principal(p) if p.AWS == "*"

is_wildcard_principal(p) if {
	some v in p.AWS
	v == "*"
}

title := "ECR repository must not grant public access"
description := "A repository resource policy that grants Allow to Principal \"*\" exposes images to the public internet. Repositories without any policy are private by default and pass this check."
