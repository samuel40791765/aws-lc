// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/crypto.h>
#include <openssl/service_indicator.h>
#include "internal.h"

#if defined(AWSLC_FIPS)
static int FIPS_service_indicator_init_state(void) {
  struct fips_service_indicator_state *indicator;
  indicator = OPENSSL_malloc(sizeof(struct fips_service_indicator_state));
  if (indicator == NULL || !CRYPTO_set_thread_local(
      AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE, indicator, OPENSSL_free)) {
    return 0;
  }
  indicator->counter = 0;
  return 1;
}

uint64_t FIPS_service_indicator_get_counter(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE);
  if (indicator == NULL) {
    return 0;
  }
  return indicator->counter;
}

// Only to be used internally, it is not intended for the user to reset the state.
int FIPS_service_indicator_reset_state(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE);
  if (indicator == NULL) {
    if(!FIPS_service_indicator_init_state()) {
      return 0;
    }
    indicator = CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE);
  }
  indicator->counter = 0;
  return 1;
}

// Only to be used internally, it is not intended for the user to update the state.
void FIPS_service_indicator_update_state(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE);
  if (indicator == NULL) {
    if(!FIPS_service_indicator_init_state()) {
      return;
    }
    indicator = CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE);
  }
  indicator->counter++;
}

#else

uint64_t FIPS_service_indicator_get_counter(void) { return 0; }

#endif // AWSLC_FIPS
