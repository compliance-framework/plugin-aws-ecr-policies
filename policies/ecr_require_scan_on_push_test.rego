package compliance_framework.ecr_require_scan_on_push

test_pass_scan_on_push_enabled if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"scan_on_push": true,
	}
}

test_fail_scan_on_push_disabled if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"scan_on_push": false,
	}
}

test_no_match_registry_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-registry",
		"scan_on_push": false,
	}
}

test_no_match_image_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
	}
}
