package compliance_framework.ecr_require_registry_scanning

test_pass_enhanced_scanning if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-registry",
		"registry_scan_type": "ENHANCED",
	}
		with data.approved_registry_scan_types as ["ENHANCED"]
}

test_fail_basic_when_enhanced_required if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-registry",
		"registry_scan_type": "BASIC",
	}
		with data.approved_registry_scan_types as ["ENHANCED"]
}

test_pass_basic_when_approved if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-registry",
		"registry_scan_type": "BASIC",
	}
		with data.approved_registry_scan_types as ["BASIC", "ENHANCED"]
}

test_fail_empty_scan_type if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-registry",
		"registry_scan_type": "",
	}
		with data.approved_registry_scan_types as ["ENHANCED"]
}

test_no_match_repository_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"registry_scan_type": "BASIC",
	}
		with data.approved_registry_scan_types as ["ENHANCED"]
}
