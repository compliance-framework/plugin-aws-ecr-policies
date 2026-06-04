package compliance_framework.ecr_require_lifecycle_policy

test_pass_has_lifecycle_policy if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"has_lifecycle_policy": true,
	}
}

test_fail_no_lifecycle_policy if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"has_lifecycle_policy": false,
	}
}

test_no_match_image_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"has_lifecycle_policy": false,
	}
}

test_no_match_registry_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-registry",
		"has_lifecycle_policy": false,
	}
}
