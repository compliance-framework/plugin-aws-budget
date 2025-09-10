package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	"github.com/aws/aws-sdk-go-v2/service/budgets/types"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	l.logger.Info("Starting eval!")

	activities := make([]*proto.Activity, 0)
	activities = append(activities, &proto.Activity{
		Title:       "Collect AWS Budget configurations",
		Description: "Using the Golang AWS SDK, fetch all Budget information and metadata.",
		Steps: []*proto.Step{
			{
				Title:       "Configure AWS Client",
				Description: "Using the default configuration loaders, create a AWS client for querying the AWS API",
			},
			{
				Title:       "Create a new AWS Budgets Client",
				Description: "In order to describe active budgets, we instantiate a new AWS Budgets client using the Golang AWS SDK.",
			},
			{
				Title:       "Describe Budgets",
				Description: "Using the newly constructed AWS client, Describe all created budgets, and store them in local memory.",
			},
		},
	})

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	budgetsClient := budgets.NewFromConfig(cfg)

	accountId := l.config["account_id"]



	// Run policy checks
	for budget, err := range getBudgets(ctx, budgetsClient, &accountId) {
		l.logger.Debug(fmt.Sprintf("Found budget: %v", aws.ToString(budget.BudgetName)))
		if err != nil {
			l.logger.Error("unable to get budget", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		alertCount := 0

		for _, err := range getNotificationsForBudget(ctx, budgetsClient, &accountId, budget.BudgetName) {
			if err != nil {
				l.logger.Error("unable to get notification", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}
			alertCount += 1
		}

		labels := map[string]string{
			"provider":    "aws", 
			"type":        "budget",
			"budget-name": aws.ToString(budget.BudgetName),
			"alert-count": fmt.Sprintf("%v", alertCount),
			"health-status": aws.ToString((*string)(&budget.HealthStatus.Status)),
		}

		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  policyManager.Pointer("reference"),
						Text: policyManager.Pointer("The Continuous Compliance Framework"),
					},
				},
			},
			{
				Title: "Continuous Compliance Framework - AWS Budget Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-aws-budget",
						Rel:  policyManager.Pointer("reference"),
						Text: policyManager.Pointer("The Continuous Compliance Framework' AWS Budget Plugin"),
					},
				},
			},
		}
		components := []*proto.Component{
			{
				Identifier:  "common-components/amazon-budgets",
				Type:        "service",
				Title:       "Amazon Budgets",
				Description: "Amazon Budgets provides functionality to track and take action on your AWS costs and usage.",
				Purpose:     "For simple-to-complex cost and usage tracking",
			},
		}
		inventory := []*proto.InventoryItem{
			{
				Identifier: fmt.Sprintf("aws-budgets/%s", aws.ToString(budget.BudgetName)),
				Type:       "budget",
				Title:      fmt.Sprintf("Amazon Budget [%s]", aws.ToString(budget.BudgetName)),
				Props: []*proto.Property{
					{
						Name:  "budget-name",
						Value: aws.ToString(budget.BudgetName),
					},
					{
						Name:  "billing-view-arn",
						Value: aws.ToString(budget.BillingViewArn),
					},
					{
						Name: "alert-count",
						Value: fmt.Sprintf("%v", alertCount),
					},
					{
						Name: "health-status",
						Value: aws.ToString((*string)(&budget.HealthStatus.Status)),
					},
				},
				ImplementedComponents: []*proto.InventoryItemImplementedComponent{
					{
						Identifier: "common-components/amazon-budgets",
					},
				},
			},
		}
		subjects := []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/amazon-budgets",
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: fmt.Sprintf("aws-budgets/%s", aws.ToString(budget.BudgetName)),
			},
		}

		evidences := make([]*proto.Evidence, 0)

		b, _ := json.Marshal(budget)
		var budgetMap map[string]interface{}
		_ = json.Unmarshal(b, &budgetMap)
		budgetMap["AlertCount"] = alertCount
		l.logger.Debug(fmt.Sprintf("Alert count is %v", alertCount))

		l.logger.Info(fmt.Sprintf("Passing budgetmap: %v", budgetMap))

		for _, policyPath := range request.GetPolicyPaths() {

			// Explicitly reset steps to make things readable
			processor := policyManager.NewPolicyProcessor(
				l.logger,
				policyManager.MergeMaps(
					labels,
					map[string]string{
						"_policy_path": policyPath,
					},
				),
				subjects,
				components,
				inventory,
				actors,
				activities,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, budgetMap)
			evidences = slices.Concat(evidences, evidence)
			l.logger.Debug(fmt.Sprintf("Evidences are %v", evidences))
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
			l.logger.Error("Failed to send evidences", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			// We don't stop here, but rather continue to the next instance
			continue
		}

		
	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func getBudgets(ctx context.Context, client *budgets.Client, accountId *string) iter.Seq2[types.Budget, error] {
	return func(yield func(types.Budget, error) bool) {
		result, err := client.DescribeBudgets(ctx, &budgets.DescribeBudgetsInput{AccountId: accountId})
		if err != nil {
			yield(types.Budget{}, err)
			return
		}

		for _, budget := range result.Budgets {
			if !yield(budget, nil) {
				return
			}
		}
	}
}

func getNotificationsForBudget(ctx context.Context, client *budgets.Client, accountId *string, budgetName *string) iter.Seq2[types.Notification, error] {
	return func(yield func(types.Notification, error) bool) {
		result, err := client.DescribeNotificationsForBudget(ctx, &budgets.DescribeNotificationsForBudgetInput{AccountId: accountId, BudgetName: budgetName})
		if err != nil {
			yield(types.Notification{}, err)
			return
		}

		for _, notification := range result.Notifications {
			if !yield(notification, nil) {
				return
			}
		}
	}

}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("Initiating AWS Budgets plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}