# METADATA
# title: Container image scan findings must be retrievable with severity data
# description: Scanned images must have returned severity-classified findings records. This proves the malware-event record retention requirement is met and that the scanning capability produces auditable output.
# custom:
#   controls:
#     - ctrl-cc6-8-010
#     - ctrl-cc7-1-011
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_scan_findings_retrievable

violation[{"id": "scan_findings_not_retrievable"}] if {
	input.resource_type == "ecr-image"
	not input.has_severity_data
}

title := "Container image scan findings must be retrievable with severity data"
description := "Scanned images must have returned severity-classified findings records. This proves the malware-event record retention requirement is met and that the scanning capability produces auditable output."

risk_templates := [{
	"name":            "scan_findings_not_retrievable",
	"title":           "Container image scan findings are not retrievable",
	"statement":       "Scan findings with severity classification cannot be retrieved for this image, preventing audit of its vulnerability history and breaking the evidence chain required to demonstrate continuous monitoring compliance.",
	"likelihood_hint": "medium",
	"impact_hint":     "medium",
	"violation_ids":   ["scan_findings_not_retrievable"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-778",
			"title":       "Insufficient Logging",
			"url":         "https://cwe.mitre.org/data/definitions/778.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title":       "Protection Mechanism Failure",
			"url":         "https://cwe.mitre.org/data/definitions/693.html"
		}
	],
	"remediation": {
		"title":       "Restore access to scan findings for the image",
		"description": "Diagnose why severity-classified findings are not being returned and restore the scanning pipeline so that auditable evidence of vulnerability status is available for every image in the lookback window.",
		"tasks": [
			{"title": "Verify that AWS Inspector or ECR scanning is fully activated for the account and region"},
			{"title": "Confirm that the IAM role used by the CCF agent has ecr:DescribeImageScanFindings permission"},
			{"title": "Re-trigger a scan for the image and wait for findings with severity data to be returned"},
			{"title": "Check for service quota limits or API throttling that may be preventing finding retrieval and raise a support case if needed"}
		]
	}
}]
