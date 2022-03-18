#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -exuo pipefail

# -e: Exit on any failure
# -x: Print the command before running
# -u: Any variable that is not set will cause an error if used
# -o pipefail: Makes sure to exit a pipeline with a non-zero error code if any command in the pipeline exists with a
#              non-zero error code.

###########################
# Main and related helper #
###########################

function script_helper() {
  cat <<EOF
This script helps kick off the device farm python script with the arguments needed.

Options:
    --help                          Displays this help menu
    --test-name						          Name of current test.
    --main-apk                      The app apk to test upon.
    --test-apk                      The testing package apk which contains the test suites.
    --devicefarm-project-arn        The devicefarm project's arn. Default to team account's.
    --devicefarm-device-pool-arn    The device pool's arn. 
    --action                        Required. The value can be:
	                                   'start-job': kicks off a device farm job.
EOF
}

function export_global_variables() {
  # If these variables are not set or empty, defaults are exported, but the |main-apk| and |test-apk| must be set.
  if [[ -z "${ANDROID_TEST_NAME+x}" || -z "${ANDROID_TEST_NAME}" ]]; then
    export ANDROID_TEST_NAME='AWS-LC Android non-FIPS Debug'
  fi
  if [[ -z "${DEVICEFARM_PROJECT+x}" || -z "${DEVICEFARM_PROJECT}" ]]; then
    export DEVICEFARM_PROJECT='arn:aws:devicefarm:us-west-2:069218930244:project:a128dad3-02e1-4ee6-84b5-143ae81cc018'
  fi
  if [[ -z "${DEVICEFARM_DEVICE_POOL+x}" || -z "${DEVICEFARM_DEVICE_POOL}" ]]; then
    export DEVICEFARM_DEVICE_POOL='arn:aws:devicefarm:us-west-2:069218930244:devicepool:a128dad3-02e1-4ee6-84b5-143ae81cc018/42508cf7-c406-4cd8-983b-2c75da210b63'
  fi
  # Other variables for managing resources.
  # DATE_NOW="$(date +%Y-%m-%d-%H-%M)"
  # export GITHUB_REPO='aws-lc'
  # export 
}

function main() {
  # parse arguments.
  while [[ $# -gt 0 ]]; do
    case ${1} in
    --help)
      script_helper
      exit 0
      ;;
    --test-name)
      export ANDROID_TEST_NAME="${2}"
      shift
      ;;
    --main-apk)
      export ANDROID_APK="${2}"
      shift
      ;;
    --test-apk)
      export ANDROID_TEST_APK="${2}"
      shift
      ;;
    --devicefarm-project-arn)
      export DEVICEFARM_PROJECT="${2}"
      shift
      ;;
    --devicefarm-device-pool-arn)
      export DEVICEFARM_DEVICE_POOL="${2}"
      shift
      ;;
    --action)
      export ACTION="${2}"
      shift
      ;;
    *)
      echo "${1} is not supported."
      exit 1
      ;;
    esac
    # Check next option -- key/value.
    shift
  done

  # Make sure action is set.
  if [[ -z "${ACTION+x}" || -z "${ACTION}" ]]; then
    echo "${ACTION} is required input."
    exit 1
  fi

  # Export global variables, which provides the contexts needed by ci setup/destroy.
  export_global_variables

  # Execute the action.
  case ${ACTION} in
  start-job)
    python3 ./devicefarm_job.py
    ;;
  *)
    echo "--action is required. Use '--help' to see allowed actions."
    exit 1
    ;;
  esac
}

# Invoke main
main "$@"