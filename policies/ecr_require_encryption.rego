# METADATA
# title: ECR repository must use an approved encryption type
# description: Repositories must be encrypted with an approved encryption type. The default AES256 (AWS-managed) encryption does not satisfy requirements for customer-managed key control.
# custom:
#   controls:
#     - ctrl-cc5-2-006
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_encryption

violation[{"id": "unapproved_encryption_type"}] if {
	input.resource_type == "ecr-repository"
	not approved_encryption(input.encryption_type)
}

approved_encryption(enc) if {
	enc == data.approved_encryption_types[_]
}

title := "ECR repository must use an approved encryption type"
description := "Repositories must be encrypted with an approved encryption type. The default AES256 (AWS-managed) encryption does not satisfy requirements for customer-managed key control."

risk_templates := [{
	"name":            "unapproved_encryption_type",
	"title":           "ECR repository uses a non-approved encryption type",
	"statement":       "The repository is not encrypted with an approved key type, reducing protection for stored images and removing the ability to enforce key rotation and access controls via a customer-managed KMS key.",
	"likelihood_hint": "medium",
	"impact_hint":     "high",
	"violation_ids":   ["unapproved_encryption_type"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-311",
			"title":       "Missing Encryption of Sensitive Data",
			"url":         "https://cwe.mitre.org/data/definitions/311.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-326",
			"title":       "Inadequate Encryption Strength",
			"url":         "https://cwe.mitre.org/data/definitions/326.html"
		}
	],
	"remediation": {
		"title":       "Re-create the ECR repository with KMS encryption",
		"description": "ECR repositories cannot have their encryption type changed in place. Create a replacement repository with the approved KMS key type, migrate images, then retire the old repository.",
		"tasks": [
			{"title": "Create a new ECR repository with the approved encryption type (KMS with a customer-managed key)"},
			{"title": "Retag and push all images from the non-compliant repository to the new repository"},
			{"title": "Update all CI/CD pipelines and workload configurations to reference the new repository URI"},
			{"title": "Delete the non-compliant repository once all references have been migrated and verified"}
		]
	}
}]
