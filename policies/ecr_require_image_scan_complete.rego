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

violation[{}] if {
	input.resource_type == "ecr-image"
	not input.scan_status == "COMPLETE"
}

title := "Container image must have a completed vulnerability scan"
description := "Images without a completed scan cannot be evaluated for vulnerabilities. Every image pushed in the lookback window must show scan_status COMPLETE before being considered for promotion."
