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
    --fips-test                     Used to direct the default device pool arn value for fips/non-fips, if devicefarm-device-pool-arn is not set. The default value is false.
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
    export DEVICEFARM_PROJECT='arn:aws:devicefarm:us-west-2:069218930244:project:e6898943-4414-4ab0-a5d5-b254e33ea53c'
  fi
  if [[ -z "${TESTING_FIPS+x}" || -z "${TESTING_FIPS}" ]]; then 
    export TESTING_FIPS=false
  fi
  if [[ -z "${DEVICEFARM_DEVICE_POOL+x}" || -z "${DEVICEFARM_DEVICE_POOL}" ]]; then
    if [[ "${TESTING_FIPS}" = true ]]; then
      # Device pool arn for FIPS.
      export DEVICEFARM_DEVICE_POOL='arn:aws:devicefarm:us-west-2:069218930244:devicepool:e6898943-4414-4ab0-a5d5-b254e33ea53c/ba9f292c-6f3b-4364-9c85-88d9aca371ce'
    else
      # Device pool arn for non-FIPS.
      export DEVICEFARM_DEVICE_POOL='arn:aws:devicefarm:us-west-2:069218930244:devicepool:e6898943-4414-4ab0-a5d5-b254e33ea53c/d62026d5-fb81-45f1-9ef4-2158d654708c'
    fi
  fim
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
    --fips-test)
      export TESTING_FIPS="${2}"
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
    set -x
    python3 ./devicefarm_job.py
    set +x
    ;;
  *)
    echo "--action is required. Use '--help' to see allowed actions."
    exit 1
    ;;
  esac
}

# Invoke main
main "$@"