# METADATA
# title: ECR registry must use an approved scanning mode
# description: The account-level registry scanning mode must be one of the approved types. ENHANCED (Inspector-backed) scanning provides continuous vulnerability detection beyond basic on-push scanning.
# custom:
#   controls:
#     - ctrl-cc5-2-006
#     - ctrl-cc5-3-025
#     - ctrl-cc7-1-001
#     - ctrl-cc7-1-002
#     - ctrl-cc7-1-006
#     - ctrl-cc7-1-011
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_registry_scanning

import future.keywords.in

violation[{}] if {
	input.resource_type == "ecr-registry"
	not approved_scan_type(input.registry_scan_type)
}

approved_scan_type(t) if {
	t in data.approved_registry_scan_types
}

title := "ECR registry must use an approved scanning mode"
description := "The account-level registry scanning mode must be one of the approved types. ENHANCED (Inspector-backed) scanning provides continuous vulnerability detection beyond basic on-push scanning."

risk_templates := [{
	"name":             "unapproved_registry_scan_type",
	"title":            "ECR registry is not using an approved scanning mode",
	"statement":        "The registry scanning mode does not meet the required standard, reducing vulnerability detection coverage.",
	"likelihood_hint":  "high",
	"impact_hint":      "high",
	"violation_ids":    ["unapproved_registry_scan_type"],
}]
