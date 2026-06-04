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

violation[{}] if {
	input.resource_type == "ecr-repository"
	not input.scan_on_push
}

title := "ECR repository must have scan-on-push enabled"
description := "Automatic image scanning on push is required for all production ECR repositories. Without it, newly pushed images are not checked for vulnerabilities."

risk_templates := [{
	"name":             "scan_on_push_disabled",
	"title":            "ECR repository scan-on-push is disabled",
	"statement":        "Automatic image scanning on push is not enabled, allowing unscanned images to be deployed.",
	"likelihood_hint":  "high",
	"impact_hint":      "high",
	"violation_ids":    ["scan_on_push_disabled"],
}]
