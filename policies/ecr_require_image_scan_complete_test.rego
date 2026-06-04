package compliance_framework.ecr_require_image_scan_complete

test_pass_scan_complete if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"scan_status": "COMPLETE",
	}
}

test_fail_scan_pending if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "IN_PROGRESS",
	}
}

test_fail_scan_failed if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "FAILED",
	}
}

test_fail_scan_unsupported if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "UNSUPPORTED",
	}
}

test_fail_scan_never_run if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "",
	}
}

test_fail_scan_status_missing if {
	# scan_status absent entirely — must not fail open
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
	}
}

test_no_match_repository_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"scan_status": "FAILED",
	}
}
