# METADATA
# title: Container image must have zero CRITICAL severity findings
# description: Images with unresolved CRITICAL findings must not be promoted to production. A non-zero CRITICAL count indicates a vulnerability that poses an immediate exploitation risk.
# custom:
#   controls:
#     - ctrl-cc6-8-004
#     - ctrl-cc6-8-006
#     - ctrl-cc6-8-008
#     - ctrl-cc7-1-010
#     - ctrl-cc8-1-016
#     - ctrl-cc8-1-017
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_no_critical_image_findings

violation[{}] if {
	input.resource_type == "ecr-image"
	input.findings_critical > 0
}

title := "Container image must have zero CRITICAL severity findings"
description := "Images with unresolved CRITICAL findings must not be promoted to production. A non-zero CRITICAL count indicates a vulnerability that poses an immediate exploitation risk."

risk_templates := [{
	"name":             "ecr_require_no_critical_image_findings",
	"title":            "Container image has unresolved CRITICAL vulnerabilities",
	"statement":        "CRITICAL severity findings indicate immediately exploitable vulnerabilities that must be remediated before promotion.",
	"likelihood_hint":  "critical",
	"impact_hint":      "critical",
	"violation_ids":    ["ecr_require_no_critical_image_findings"],
}]
