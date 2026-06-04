package compliance_framework.ecr_require_no_critical_image_findings

test_pass_zero_critical if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"scan_status": "COMPLETE",
		"findings_critical": 0,
	}
}

test_fail_one_critical if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "COMPLETE",
		"findings_critical": 1,
	}
}

test_fail_many_critical if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"scan_status": "COMPLETE",
		"findings_critical": 100,
	}
}

# Boundary: exactly zero is the threshold
test_pass_boundary_zero if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"findings_critical": 0,
	}
}

test_fail_boundary_one if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"findings_critical": 1,
	}
}

test_no_match_repository_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"findings_critical": 10,
	}
}
