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

violation[{"id": "critical_vulnerabilities_found"}] if {
	input.resource_type == "ecr-image"
	input.findings_critical > 0
}

title := "Container image must have zero CRITICAL severity findings"
description := "Images with unresolved CRITICAL findings must not be promoted to production. A non-zero CRITICAL count indicates a vulnerability that poses an immediate exploitation risk."

risk_templates := [{
	"name":            "critical_vulnerabilities_found",
	"title":           "Container image has unresolved CRITICAL vulnerabilities",
	"statement":       "CRITICAL severity findings indicate immediately exploitable vulnerabilities in the image. Deploying this image exposes workloads to active exploitation and must be blocked until all CRITICAL findings are resolved.",
	"likelihood_hint": "critical",
	"impact_hint":     "critical",
	"violation_ids":   ["critical_vulnerabilities_found"],
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
		"title":       "Remediate all CRITICAL severity findings before promoting the image",
		"description": "Update the affected packages or base image to patched versions, rebuild the image, and re-scan before allowing promotion to production.",
		"tasks": [
			{"title": "Review CRITICAL findings in ECR or AWS Inspector to identify the affected packages and CVEs"},
			{"title": "Update the affected base image or package versions to patched releases that resolve the findings"},
			{"title": "Rebuild and re-push the image, then confirm the new digest has zero CRITICAL findings"},
			{"title": "Block pipeline promotion of the original digest and update all deployment references to the remediated image"}
		]
	}
}]
