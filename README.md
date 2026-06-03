# plugin-aws-ecr-policies

OPA policy bundle for the [plugin-aws-ecr](https://github.com/container-solutions/plugin-aws-ecr) CCF compliance plugin.

## Policies

### CONFIG — repository checks

| Policy | Description | Controls |
|--------|-------------|---------|
| `ecr_require_scan_on_push` | Repository must have scan-on-push enabled | ctrl-cc5-3-025, ctrl-cc6-8-001/002/003/009/011/012, ctrl-cc7-1-001/006 |
| `ecr_require_tag_immutability` | Repository must enforce `IMMUTABLE` image tags | ctrl-cc6-8-002/005/007, ctrl-cc8-1-001/008/014 |
| `ecr_require_encryption` | Repository encryption type must be approved | ctrl-cc5-2-006 |
| `ecr_require_lifecycle_policy` | Repository must have a lifecycle policy | ctrl-cc6-5-001 |
| `ecr_deny_public_access` | Repository policy must not grant wildcard principal access | ctrl-cc6-8-005/013, ctrl-cc8-1-014/015 |
| `ecr_require_tags` | Repository must carry all required tags | CC6.1 |

### CONFIG — registry checks

| Policy | Description | Controls |
|--------|-------------|---------|
| `ecr_require_registry_scanning` | Registry scan mode must be approved | ctrl-cc5-2-006/003, ctrl-cc7-1-001/002/006/011 |

### DYNAMIC — image checks (90-day lookback)

| Policy | Description | Controls |
|--------|-------------|---------|
| `ecr_require_image_scan_complete` | Image scan must be `COMPLETE` | ctrl-cc3-2-011, ctrl-cc5-2-007, ctrl-cc7-1-004/005, ctrl-cc8-1-016/017 |
| `ecr_require_no_critical_image_findings` | Image must have zero `CRITICAL` findings | ctrl-cc6-8-004/006/008, ctrl-cc7-1-010, ctrl-cc8-1-016/017 |
| `ecr_require_no_high_image_findings` | Image `HIGH` findings must be ≤ threshold | ctrl-cc6-8-004/006/008, ctrl-cc7-1-010, ctrl-cc8-1-016/017 |
| `ecr_require_scan_findings_retrievable` | Scan findings with severity data must be accessible | ctrl-cc6-8-010, ctrl-cc7-1-011 |

## `data.json` reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `approved_encryption_types` | `[]string` | `["KMS"]` | Allowed `encryptionType` values |
| `approved_registry_scan_types` | `[]string` | `["ENHANCED"]` | Allowed registry `scanType` values |
| `required_repository_tags` | `[]string` | `["Environment","Owner"]` | Tags required on every repository |
| `required_tag_values` | `object` | `{}` | Tag key → required value enforcement |
| `image_lookback_days` | `number` | `90` | Days back to evaluate images (used by plugin) |
| `max_high_finding_count` | `number` | `0` | Maximum HIGH findings allowed per image |

## Adding a new policy

1. Create `policies/ecr_<check_name>.rego` with a `# METADATA` block, package `compliance_framework.ecr_<check_name>`, and guard your `violation` rule with `input.resource_type == "ecr-repository"` (or `ecr-registry` / `ecr-image`).
2. Create `policies/ecr_<check_name>_test.rego` with at minimum one pass test, one fail test, and boundary tests for any numeric threshold.
3. Run `make test` — all tests must pass before committing.
4. Add the policy to the table above.

## Development

```bash
# Run all OPA tests
make test

# Validate policy syntax
make validate

# Build the bundle tar.gz
make build
```
