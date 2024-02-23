#!/bin/bash

set -eu

ENVIRONMENT=$1
JOB_NAME=$2

NETWORK_CONFIG=$(aws ecs describe-services --cluster delta-auth-service-cluster-${ENVIRONMENT} --services ecs-service-${ENVIRONMENT} --query 'services[0].deployments[0].networkConfiguration')

aws ecs run-task \
  --cluster "delta-auth-service-cluster-${ENVIRONMENT}" \
  --task-definition "delta-auth-service-${ENVIRONMENT}" \
  --launch-type FARGATE \
  --network-configuration "${NETWORK_CONFIG}" \
  --overrides "{\"containerOverrides\":[{\"environment\":[{\"name\":\"RUN_TASK\",\"value\":\"${JOB_NAME}\"}],\"name\":\"delta-auth-service-container-${ENVIRONMENT}\"}]}"
