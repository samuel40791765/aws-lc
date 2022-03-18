#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from util.env_util import EnvUtil

# Used when AWS CDK defines AWS resources.
AWS_ACCOUNT = EnvUtil.get("CDK_DEPLOY_ACCOUNT", "620771051181")
AWS_REGION = EnvUtil.get("CDK_DEPLOY_REGION", "us-west-2")

# Used when AWS CDK defines ECR repos.
LINUX_AARCH_ECR_REPO = EnvUtil.get("ECR_LINUX_AARCH_REPO_NAME", "aws-lc-docker-images-linux-aarch")
LINUX_X86_ECR_REPO = EnvUtil.get("ECR_LINUX_X86_REPO_NAME", "aws-lc-docker-images-linux-x86")
WINDOWS_X86_ECR_REPO = EnvUtil.get("ECR_WINDOWS_X86_REPO_NAME", "aws-lc-docker-images-windows-x86")

# Used when AWS CodeBuild needs to create web_hooks.
GITHUB_REPO_OWNER = EnvUtil.get("GITHUB_REPO_OWNER", "awslabs")
GITHUB_REPO_NAME = EnvUtil.get("GITHUB_REPO_NAME", "aws-lc")
GITHUB_SOURCE_VERSION = EnvUtil.get("GITHUB_SOURCE_VERSION", "main")

# Used when AWS CDK defines resources for Windows docker image build.
S3_BUCKET_NAME = EnvUtil.get("S3_FOR_WIN_DOCKER_IMG_BUILD", "aws-lc-windows-docker-image-build")
WIN_EC2_TAG_KEY = EnvUtil.get("WIN_EC2_TAG_KEY", "aws-lc")
WIN_EC2_TAG_VALUE = EnvUtil.get("WIN_EC2_TAG_VALUE", "aws-lc-windows-docker-image-build")
SSM_DOCUMENT_NAME = EnvUtil.get("WIN_DOCKER_BUILD_SSM_DOCUMENT", "windows-ssm-document")

# Used for AWS Device Farm python kick off script.
APK = EnvUtil.get("APK", None)
TEST_APK = EnvUtil.get("TEST_APK", None)
DEVICEFARM_PROJECT = EnvUtil.get("DEVICEFARM_PROJECT", "arn:aws:devicefarm:us-west-2:069218930244:project:a128dad3-02e1-4ee6-84b5-143ae81cc018")
DEVICEFARM_DEVICE_POOL = EnvUtil.get("DEVICEFARM_DEVICE_POOL", "arn:aws:devicefarm:us-west-2:069218930244:devicepool:a128dad3-02e1-4ee6-84b5-143ae81cc018/42508cf7-c406-4cd8-983b-2c75da210b63")
ANDROID_TEST_NAME = EnvUtil.get("ANDROID_TEST_NAME", "AWS-LC Android Test")