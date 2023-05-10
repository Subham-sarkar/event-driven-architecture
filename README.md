# Event Driven Architecture

## Overview

ELM Automation is a powerful tool that enables the automatic updating of exception status in the Config-ResourceExceptions table in the production account for all deleted exceptions across multiple target accounts. With ELM Automation, you can streamline your exception management process and ensure that your systems remain secure and compliant at all times. This is an example of an event based system.


## Types of Exceptions

When working with AWS Config, it's important to understand the different types of exceptions that can occur. There are three main exception types: SIMPLE Exception (Resource ID), SIMPLE Exception (Resource ARN), and COMPOSITE Exceptions.
SIMPLE Exceptions occur when a single resource is marked as an exception in the AWS Config rule. This can be done using either the resource ID or the resource ARN, depending on the use case.
COMPOSITE Exceptions, on the other hand, occur when multiple resources are marked as exceptions for a single AWS Config rule. This is useful when you want to apply a single exception to a group of resources instead of applying the exception to each resource individually.
By understanding these exception types, you can effectively manage your AWS Config rules and ensure that your resources are always in compliance with our organization's policies and standards.


## Architecture at a Glance

![ELM Architecture](C:\Users\91891\Documents\MyFiles\Config_Team\Exception_Deletion\DOCS\ELM_Architecture_Diagram.png)

The ELM automation framework consists of three main components:
	elm-send-events.yaml
	elm-status-update.yaml
	elm-status-update.py

The ELM architecture is an advanced exception management system designed to automate the process of updating the exception status of deleted resources in the Config-ResourceExceptions table. To achieve this, the architecture employs a sophisticated network of Event Bridge rules, an SQS queue, and a Lambda function.

First, an Event Bridge rule is established in all target accounts across all regions that are Config-enabled. This rule monitors the deletion of exception resources using an event pattern and sends the compliance change notification to the production account's default bus in us-east-1. The event rule has appropriate permission to send to the default bus in the production account.

Upon receipt of the notification by the default bus in the production account, another Event Bridge rule monitors the notification and sends it to an SQS queue. This, in turn, triggers a Lambda function, which then updates the status of the exception record as RESOURCE_DELETED in the Config_ResourceExceptions table. The Lambda function also sets the TTL to the required epoch value so that the record gets deleted by DynamoDB itself.

With the ELM architecture, you can achieve a high degree of automation and efficiency in your exception management process. This ensures that your systems remain secure and compliant, and that you can focus on other critical aspects of your business operations.


## Automation Components

The ELM automation framework consists of three main components:
	elm-send-events.yaml
	elm-status-update.yaml
	elm-status-update.py.

The first component, elm-send-events.yaml, sets up the default Event Bridge rule and IAM role in all target accounts, which enables sending compliance change notifications to the production account in the us-east-1 region.

The second component, elm-status-update.yaml, updates the exception status in the Config-ResourceExceptions table using AWS Lambda and DynamoDB. It checks for simple and composite exceptions and confirms the deletion of resources in target accounts using config.list_discovered_resources api call via assuming Role-Config-Mgmt.

The third component, elm-status-update.py, fetches all composite exceptions using a filter expression and loops over and updates all exceptions in the table. With these components, you can easily manage exceptions and ensure the security and compliance of your AWS resources.


## Event Pattern:

detail:
    messageType:
        - "ComplianceChangeNotification"
    configRuleName:
        - prefix: !If [CreateProdResources, 'prod-', !Sub '${Environment}-']
    oldEvaluationResult:
        complianceType:
            - COMPLIANT
            - NON_COMPLIANT
        annotation:
            - This resource is an exception.
            - Recorded exception has expired.
            - Recorded exception has been deleted because of no recertification.
    newEvaluationResult:
        complianceType:
            - NOT_APPLICABLE
        annotation:
            - prefix: Resource was deleted

