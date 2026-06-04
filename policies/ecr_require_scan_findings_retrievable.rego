# METADATA
# title: Container image scan findings must be retrievable with severity data
# description: Scanned images must have returned severity-classified findings records. This proves the malware-event record retention requirement is met and that the scanning capability produces auditable output.
# custom:
#   controls:
#     - ctrl-cc6-8-010
#     - ctrl-cc7-1-011
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_scan_findings_retrievable

violation[{}] if {
	input.resource_type == "ecr-image"
	not input.has_severity_data
}

title := "Container image scan findings must be retrievable with severity data"
description := "Scanned images must have returned severity-classified findings records. This proves the malware-event record retention requirement is met and that the scanning capability produces auditable output."

risk_templates := [{
	"name":             "ecr_require_scan_findings_retrievable",
	"title":            "Container image scan findings are not retrievable",
	"statement":        "Scan findings cannot be retrieved, preventing audit of vulnerability history for this image.",
	"likelihood_hint":  "medium",
	"impact_hint":      "medium",
	"violation_ids":    ["ecr_require_scan_findings_retrievable"],
}]
