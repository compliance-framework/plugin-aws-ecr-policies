package compliance_framework.ecr_require_tags

test_pass_all_required_tags_present if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"tags": {"Environment": "prod", "Owner": "platform"},
	}
		with data.required_repository_tags as ["Environment", "Owner"]
		with data.required_tag_values as {}
}

test_fail_missing_one_tag if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"tags": {"Environment": "prod"},
	}
		with data.required_repository_tags as ["Environment", "Owner"]
		with data.required_tag_values as {}
}

test_fail_missing_all_tags if {
	count(violation) == 2 with input as {
		"resource_type": "ecr-repository",
		"tags": {},
	}
		with data.required_repository_tags as ["Environment", "Owner"]
		with data.required_tag_values as {}
}

test_pass_no_required_tags if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"tags": {},
	}
		with data.required_repository_tags as []
		with data.required_tag_values as {}
}

test_fail_required_tag_wrong_value if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"tags": {"Environment": "dev", "Owner": "team"},
	}
		with data.required_repository_tags as ["Environment", "Owner"]
		with data.required_tag_values as {"Environment": "prod"}
}

test_pass_required_tag_correct_value if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"tags": {"Environment": "prod", "Owner": "team"},
	}
		with data.required_repository_tags as ["Environment", "Owner"]
		with data.required_tag_values as {"Environment": "prod"}
}

test_fail_required_tag_missing_but_value_required if {
	# Tag is absent from input.tags but appears in required_tag_values.
	# Only the missing_tag violation should fire; invalid_tag_value must NOT fire.
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"tags": {"Owner": "team"},
	}
		with data.required_repository_tags as ["Environment", "Owner"]
		with data.required_tag_values as {"Environment": "prod"}
}

test_no_match_image_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"tags": {},
	}
		with data.required_repository_tags as ["Environment"]
		with data.required_tag_values as {}
}
