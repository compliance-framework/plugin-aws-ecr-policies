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

violation[{}] if {
	input.resource_type == "ecr-registry"
	not approved_scan_type(input.registry_scan_type)
}

approved_scan_type(t) if {
	t == data.approved_registry_scan_types[_]
}

title := "ECR registry must use an approved scanning mode"
description := "The account-level registry scanning mode must be one of the approved types. ENHANCED (Inspector-backed) scanning provides continuous vulnerability detection beyond basic on-push scanning."
