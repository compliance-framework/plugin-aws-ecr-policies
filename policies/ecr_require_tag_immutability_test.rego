package compliance_framework.ecr_require_tag_immutability

test_pass_immutable if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"image_tag_immutability": "IMMUTABLE",
	}
}

test_fail_mutable if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"image_tag_immutability": "MUTABLE",
	}
}

test_fail_empty_setting if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"image_tag_immutability": "",
	}
}

test_no_match_image_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"image_tag_immutability": "MUTABLE",
	}
}
