# Compliance Framework - AWS Budget Plugin

Fetches information regarding AWS Billing, including
- Whether there is a budget in place

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide AWS credentials in one of the following forms:

- Access key 



## Configuration

```yaml
plugins:
  aws_budget:
    # Token for user with access to costs & billing API
    access-key-id: ""
    secret-access-key: ""
    # additionaly define a session-token for an assumed role:
    session-token: ""
    # ID of the AWS Account that you want to check budgets for
    account-id: 123456789012
```

## Integration testing

This plugin contains unit tests as well as integration tests.

The integration tests need AWS credentials to call the AWS API.

```shell
GITHUB_TOKEN="<TOKEN>" go test ./... -v --tags integration
```

## Policies

When writing OPA/Rego policies for this plugin, they must be added under the `compliance_framework` Rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

## Releases

This plugin is released using GoReleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub Releases page.

You can find the OCI implementations in the GitHub Packages page.
