package compliance_framework.ecr_require_no_high_image_findings

test_pass_zero_high_with_threshold_zero if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"findings_high": 0,
	}
		with data.max_high_finding_count as 0
}

test_fail_one_high_with_threshold_zero if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"findings_high": 1,
	}
		with data.max_high_finding_count as 0
}

test_pass_within_threshold if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"findings_high": 5,
	}
		with data.max_high_finding_count as 5
}

test_fail_exceeds_threshold if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"findings_high": 6,
	}
		with data.max_high_finding_count as 5
}

# Boundary: exactly at threshold is a pass
test_pass_boundary_at_threshold if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"findings_high": 3,
	}
		with data.max_high_finding_count as 3
}

# Boundary: one above threshold is a fail
test_fail_boundary_one_above if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-image",
		"findings_high": 4,
	}
		with data.max_high_finding_count as 3
}

test_no_match_repository_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"findings_high": 10,
	}
		with data.max_high_finding_count as 0
}
