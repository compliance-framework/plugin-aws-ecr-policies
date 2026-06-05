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

violation[{"id": "high_vulnerabilities_exceed_threshold"}] if {
	input.resource_type == "ecr-image"
	input.findings_high > data.max_high_finding_count
}

title := "Container image must not exceed the HIGH severity finding threshold"
description := "Images with HIGH severity finding counts above the configured threshold must not be promoted. The threshold is configurable via max_high_finding_count in data.json (default 0)."

risk_templates := [{
	"name":            "high_vulnerabilities_exceed_threshold",
	"title":           "Container image exceeds the HIGH vulnerability threshold",
	"statement":       "The number of HIGH severity findings exceeds the configured threshold, indicating an unacceptable level of exploitable risk that must be reduced before the image is eligible for production promotion.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["high_vulnerabilities_exceed_threshold"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-1035",
			"title":       "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities",
			"url":         "https://cwe.mitre.org/data/definitions/1035.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-1104",
			"title":       "Use of Unmaintained Third Party Components",
			"url":         "https://cwe.mitre.org/data/definitions/1104.html"
		}
	],
	"remediation": {
		"title":       "Reduce the HIGH severity finding count to at or below the configured threshold",
		"description": "Update affected packages or the base image to bring the HIGH finding count within the allowed threshold defined in max_high_finding_count. If the threshold needs to be revised, update data.json with documented justification.",
		"tasks": [
			{"title": "Review HIGH findings in ECR or AWS Inspector to identify the affected packages and CVEs"},
			{"title": "Update the affected base image or package versions to patched releases that reduce the HIGH count"},
			{"title": "Rebuild and re-push the image, then confirm the new digest meets the threshold"},
			{"title": "If a temporary threshold exception is required, update max_high_finding_count in data.json with a documented justification and a target remediation date"}
		]
	}
}]
