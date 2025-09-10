# Compliance Framework - AWS Budget Plugin

Fetches information regarding AWS Billing, including
- Whether there is a budget in place

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide AWS credentials in one of the following forms:

- Access key 



## Configuration

Configuration must contain an AWS account ID. Additionally, role credentials can be passed through the configuration, otherwise they will attempt to be found from the environment. Optionally, you can also define a role ARN to assume which will be used to retrieve the relevant budget data.

```yaml
plugins:
  aws_budget:
    # ID of the AWS Account that you want to check budgets for
    account-id: 123456789012
    # (Optional) Federated credentials to use
    access-key-id: "..."
    secret-access-key: "..."
    session-token: "..."
    # (Optional) Role to assume for retrieving budgets data
    assume-role-arn: "arn:aws:iam::123456789012:role/example-role"
```

If a role is defined, it must have the following policy statement as a minimum:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSBudgetsPermissions",
            "Effect": "Allow",
            "Action": [
                "budgets:ViewBudget"
            ],
            "Resource": "arn:aws:budgets::<account-id>:budget/*"
        }
    ]
}
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
