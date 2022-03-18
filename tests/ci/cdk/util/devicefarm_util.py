#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from util.env_util import EnvUtil

# Used for AWS Device Farm python kick off script.
ANDROID_APK = EnvUtil.get("ANDROID_APK", None)
ANDROID_TEST_APK = EnvUtil.get("ANDROID_TEST_APK", None)
DEVICEFARM_PROJECT = EnvUtil.get("DEVICEFARM_PROJECT", "arn:aws:devicefarm:us-west-2:069218930244:project:a128dad3-02e1-4ee6-84b5-143ae81cc018")
DEVICEFARM_DEVICE_POOL = EnvUtil.get("DEVICEFARM_DEVICE_POOL", "arn:aws:devicefarm:us-west-2:069218930244:devicepool:a128dad3-02e1-4ee6-84b5-143ae81cc018/42508cf7-c406-4cd8-983b-2c75da210b63")
ANDROID_TEST_NAME = EnvUtil.get("ANDROID_TEST_NAME", "AWS-LC Android Test")