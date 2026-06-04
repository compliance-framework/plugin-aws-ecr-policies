package compliance_framework.ecr_require_scan_findings_retrievable

test_pass_has_severity_data if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"scan_status": "COMPLETE",
		"has_severity_data": true,
	}
}

test_pass_clean_image_with_severity_data if {
	# A clean image (no CVEs) with a completed scan still has severity data available
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"scan_status": "COMPLETE",
		"findings_critical": 0,
		"findings_high": 0,
		"has_severity_data": true,
	}
}

test_fail_no_severity_data_scan_not_run if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "UNSUPPORTED",
		"has_severity_data": false,
	}
}

test_fail_no_severity_data_scan_failed if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "FAILED",
		"has_severity_data": false,
	}
}

test_fail_scan_pending_no_data if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "IN_PROGRESS",
		"has_severity_data": false,
	}
}

test_no_match_repository_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"has_severity_data": false,
	}
}
