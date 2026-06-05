# METADATA
# title: Container image must have a completed vulnerability scan
# description: Images without a completed scan cannot be evaluated for vulnerabilities. Every image pushed in the lookback window must show scan_status COMPLETE before being considered for promotion.
# custom:
#   controls:
#     - ctrl-cc3-2-011
#     - ctrl-cc5-2-007
#     - ctrl-cc7-1-004
#     - ctrl-cc7-1-005
#     - ctrl-cc8-1-016
#     - ctrl-cc8-1-017
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_image_scan_complete

violation[{"id": "image_scan_not_complete"}] if {
	input.resource_type == "ecr-image"
	not input.scan_status == "COMPLETE"
}

title := "Container image must have a completed vulnerability scan"
description := "Images without a completed scan cannot be evaluated for vulnerabilities. Every image pushed in the lookback window must show scan_status COMPLETE before being considered for promotion."

risk_templates := [{
	"name":            "image_scan_not_complete",
	"title":           "Container image has not been vulnerability scanned",
	"statement":       "An image without a completed scan cannot be verified free of known vulnerabilities before deployment, meaning exploitable packages may reach production undetected.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["image_scan_not_complete"],
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
		"title":       "Ensure a completed vulnerability scan exists for the image",
		"description": "Verify that scan-on-push is enabled for the repository, then trigger a manual scan for any image that was pushed before scanning was configured. Block deployment pipeline promotion until scan_status reaches COMPLETE.",
		"tasks": [
			{"title": "Confirm that scan-on-push is enabled on the parent repository"},
			{"title": "Trigger a manual image scan via the AWS Console or CLI for images without a completed scan"},
			{"title": "Monitor scan status until COMPLETE is returned and findings are available"},
			{"title": "Add a deployment gate in CI/CD pipelines that blocks promotion until scan_status is COMPLETE"}
		]
	}
}]
