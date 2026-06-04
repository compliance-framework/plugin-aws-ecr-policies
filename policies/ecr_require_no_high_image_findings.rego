# METADATA
# title: Container image must not exceed the HIGH severity finding threshold
# description: Images with HIGH severity finding counts above the configured threshold must not be promoted. The threshold is configurable via max_high_finding_count in data.json (default 0).
# custom:
#   controls:
#     - ctrl-cc6-8-004
#     - ctrl-cc6-8-006
#     - ctrl-cc6-8-008
#     - ctrl-cc7-1-010
#     - ctrl-cc8-1-016
#     - ctrl-cc8-1-017
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_no_high_image_findings

violation[{}] if {
	input.resource_type == "ecr-image"
	input.findings_high > data.max_high_finding_count
}

title := "Container image must not exceed the HIGH severity finding threshold"
description := "Images with HIGH severity finding counts above the configured threshold must not be promoted. The threshold is configurable via max_high_finding_count in data.json (default 0)."

risk_templates := [{
	"name":             "high_vulnerabilities_exceed_threshold",
	"title":            "Container image exceeds the HIGH vulnerability threshold",
	"statement":        "The number of HIGH severity findings exceeds the configured threshold for safe deployment.",
	"likelihood_hint":  "high",
	"impact_hint":      "high",
	"violation_ids":    ["high_vulnerabilities_exceed_threshold"],
}]
