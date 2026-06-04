# METADATA
# title: ECR repository must use an approved encryption type
# description: Repositories must be encrypted with an approved encryption type. The default AES256 (AWS-managed) encryption does not satisfy requirements for customer-managed key control.
# custom:
#   controls:
#     - ctrl-cc5-2-006
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_encryption

violation[{}] if {
	input.resource_type == "ecr-repository"
	not approved_encryption(input.encryption_type)
}

approved_encryption(enc) if {
	enc == data.approved_encryption_types[_]
}

title := "ECR repository must use an approved encryption type"
description := "Repositories must be encrypted with an approved encryption type. The default AES256 (AWS-managed) encryption does not satisfy requirements for customer-managed key control."

risk_templates := [{
	"name":             "ecr_require_encryption",
	"title":            "ECR repository uses a non-approved encryption type",
	"statement":        "Repository is not encrypted with an approved key type, reducing protection for stored images.",
	"likelihood_hint":  "medium",
	"impact_hint":      "high",
	"violation_ids":    ["ecr_require_encryption"],
}]
