# METADATA
# title: ECR repository must enforce image tag immutability
# description: Mutable image tags allow silent overwriting of production references without detection. Immutable tags prevent unauthorised substitution and support deployment validation.
# custom:
#   controls:
#     - ctrl-cc6-8-002
#     - ctrl-cc6-8-005
#     - ctrl-cc6-8-007
#     - ctrl-cc8-1-001
#     - ctrl-cc8-1-008
#     - ctrl-cc8-1-014
#   schedule: "0 */6 * * *"

package compliance_framework.ecr_require_tag_immutability

violation[{}] if {
	input.resource_type == "ecr-repository"
	input.image_tag_immutability != "IMMUTABLE"
}

title := "ECR repository must enforce image tag immutability"
description := "Mutable image tags allow silent overwriting of production references without detection. Immutable tags prevent unauthorised substitution and support deployment validation."
