# METADATA
# title: ECR repository must have scan-on-push enabled
# description: Automatic image scanning on push is required for all production ECR repositories. Without it, newly pushed images are not checked for vulnerabilities.
# custom:
#   controls:
#     - ctrl-cc5-3-025
#     - ctrl-cc6-8-001
#     - ctrl-cc6-8-002
#     - ctrl-cc6-8-003
#     - ctrl-cc6-8-009
#     - ctrl-cc6-8-011
#     - ctrl-cc6-8-012
#     - ctrl-cc7-1-001
#     - ctrl-cc7-1-006
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_scan_on_push

violation[{"id": "scan_on_push_disabled"}] if {
	input.resource_type == "ecr-repository"
	not input.scan_on_push
}

title := "ECR repository must have scan-on-push enabled"
description := "Automatic image scanning on push is required for all production ECR repositories. Without it, newly pushed images are not checked for vulnerabilities."

risk_templates := [{
	"name":            "scan_on_push_disabled",
	"title":           "ECR repository scan-on-push is disabled",
	"statement":       "Automatic image scanning on push is not enabled, allowing unscanned images to be deployed without any vulnerability check.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["scan_on_push_disabled"],
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
		"title":       "Enable scan-on-push for the ECR repository",
		"description": "Configure the repository to automatically scan every image on push so vulnerabilities are detected before deployment.",
		"tasks": [
			{"title": "Enable scan-on-push in the repository image scanning settings"},
			{"title": "Trigger a manual scan on recently pushed images that were not scanned on arrival"},
			{"title": "Monitor ECR or AWS Inspector for findings produced by the initial scans"},
			{"title": "Confirm the scan-on-push setting is enforced in infrastructure-as-code and CI/CD pipelines"}
		]
	}
}]
