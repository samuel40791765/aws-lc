#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from util.env_util import EnvUtil

# Used when AWS CDK defines AWS resources.
APK = EnvUtil.get("APK", "620771051181")
TEST_APK = EnvUtil.get("TEST_APK", "us-west-2")

# Used when AWS CDK defines ECR repos.
DEVICEFARM_PROJECT = EnvUtil.get("DEVICEFARM_PROJECT", "aws-lc-docker-images-linux-aarch")
DEVICEFARM_DEVICE_POOL = EnvUtil.get("DEVICEFARM_DEVICE_POOL", "aws-lc-docker-images-linux-x86")
ANDROID_TEST_NAME = EnvUtil.get("ANDROID_TEST_NAME", "AWS-LC Android Test")