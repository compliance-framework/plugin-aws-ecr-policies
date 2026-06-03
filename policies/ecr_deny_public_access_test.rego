package compliance_framework.ecr_deny_public_access

test_pass_no_repository_policy if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": false,
		"repository_policy_text": "",
	}
}

test_pass_policy_with_specific_principal if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": true,
		"repository_policy_text": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/ci"},"Action":"ecr:GetDownloadUrlForLayer"}]}`,
	}
}

test_fail_wildcard_principal_string if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": true,
		"repository_policy_text": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:GetDownloadUrlForLayer"}]}`,
	}
}

test_fail_wildcard_principal_aws_object if {
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": true,
		"repository_policy_text": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:GetDownloadUrlForLayer"}]}`,
	}
}

test_pass_deny_statement_with_wildcard if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": true,
		"repository_policy_text": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"ecr:*"}]}`,
	}
}

test_fail_unparseable_policy_text if {
	# Malformed JSON with has_repository_policy=true must fail-closed (not fail-open)
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": true,
		"repository_policy_text": `not-valid-json`,
	}
}

test_fail_single_object_statement_wildcard if {
	# Statement is a single object (not array) — should still be detected
	count(violation) == 1 with input as {
		"resource_type": "ecr-repository",
		"has_repository_policy": true,
		"repository_policy_text": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"ecr:GetDownloadUrlForLayer"}}`,
	}
}

test_no_match_image_resource if {
	count(violation) == 0 with input as {
		"resource_type": "ecr-image",
		"has_repository_policy": true,
		"repository_policy_text": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:GetDownloadUrlForLayer"}]}`,
	}
}
