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
	"name":            "unapproved_registry_scan_type",
	"title":           "ECR registry is not using an approved scanning mode",
	"statement":       "The registry scanning mode does not meet the required standard, reducing vulnerability detection coverage and removing continuous re-scanning of images that have already been pushed.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["unapproved_registry_scan_type"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title":       "Protection Mechanism Failure",
			"url":         "https://cwe.mitre.org/data/definitions/693.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-1104",
			"title":       "Use of Unmaintained Third Party Components",
			"url":         "https://cwe.mitre.org/data/definitions/1104.html"
		}
	],
	"remediation": {
		"title":       "Enable ENHANCED scanning at the ECR registry level",
		"description": "Switch the registry scanning configuration to ENHANCED mode backed by AWS Inspector so that images receive continuous re-scanning when new CVEs are published, not just on initial push.",
		"tasks": [
			{"title": "Activate AWS Inspector in the account and region where the registry operates"},
			{"title": "Set the ECR registry scanning type to ENHANCED in the registry scanning configuration"},
			{"title": "Configure scan filters to include all repositories or target the specific repositories required by policy"},
			{"title": "Verify that Inspector is producing findings and that the registry scan type shows ENHANCED in the AWS Console"}
		]
	}
}]
