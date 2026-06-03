package compliance_framework.ecr_require_encryption

test_pass_kms if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"encryption_type": "KMS",
	}
		with data.approved_encryption_types as ["KMS"]
}

test_fail_aes256_when_kms_required if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"encryption_type": "AES256",
	}
		with data.approved_encryption_types as ["KMS"]
}

test_pass_aes256_when_approved if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"encryption_type": "AES256",
	}
		with data.approved_encryption_types as ["AES256", "KMS"]
}

test_fail_empty_encryption_type if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"encryption_type": "",
	}
		with data.approved_encryption_types as ["KMS"]
}

test_no_match_image_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"encryption_type": "AES256",
	}
		with data.approved_encryption_types as ["KMS"]
}
