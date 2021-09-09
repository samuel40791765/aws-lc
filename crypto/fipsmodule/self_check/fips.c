/* Copyright (c) 2017, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/crypto.h>

#include "../../internal.h"
#include "../delocate.h"


int FIPS_mode(void) {
#if defined(BORINGSSL_FIPS) && !defined(OPENSSL_ASAN)
  return 1;
#else
  return 0;
#endif
}

int FIPS_mode_set(int on) { return on == FIPS_mode(); }

#if defined(BORINGSSL_FIPS_COUNTERS)

size_t FIPS_read_counter(enum fips_counter_t counter) {
  if (counter < 0 || counter > fips_counter_max) {
    abort();
  }

  const size_t *array =
      CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_FIPS_COUNTERS);
  if (!array) {
    return 0;
  }

  return array[counter];
}

void boringssl_fips_inc_counter(enum fips_counter_t counter) {
  if (counter < 0 || counter > fips_counter_max) {
    abort();
  }

  size_t *array =
      CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_FIPS_COUNTERS);
  if (!array) {
    const size_t num_bytes = sizeof(size_t) * (fips_counter_max + 1);
    array = OPENSSL_malloc(num_bytes);
    if (!array) {
      return;
    }

    OPENSSL_memset(array, 0, num_bytes);
    if (!CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_FIPS_COUNTERS, array,
                                 OPENSSL_free)) {
      // |OPENSSL_free| has already been called by |CRYPTO_set_thread_local|.
      return;
    }
  }

  array[counter]++;
}

#else

size_t FIPS_read_counter(enum fips_counter_t counter) { return 0; }

// boringssl_fips_inc_counter is a no-op, inline function in internal.h in this
// case. That should let the compiler optimise away the callsites.

#endif

// FIPS struct experiment @sachiang

// #if defined(BORINGSSL_FIPS)

struct fips_service_indicator_state {
  int counter;
};

void awslc_fips_service_indicator_init_counter(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  if (!indicator) {
    indicator = OPENSSL_malloc(sizeof(struct fips_service_indicator_state));
    if (!indicator || !CRYPTO_set_thread_local(
  AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER, indicator, OPENSSL_free)) {
      return;
    }
  }
  indicator->counter = 0;
}

int awslc_fips_service_indicator_get_counter(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  if (!indicator) {
    awslc_fips_service_indicator_init_counter();
    indicator = CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  }
  return indicator->counter;
}

void awslc_fips_service_indicator_reset_counter(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  if (!indicator) {
    awslc_fips_service_indicator_init_counter();
    indicator = CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  }
  indicator->counter = 0;
}

void awslc_fips_service_indicator_inc_counter(void) {
  struct fips_service_indicator_state *indicator =
      CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  if (!indicator) {
    awslc_fips_service_indicator_init_counter();
    indicator = CRYPTO_get_thread_local(AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_COUNTER);
  }
  indicator->counter++;
}

int awslc_fips_check_service_approved(int counter) {
  if(awslc_fips_service_indicator_get_counter() > counter) {
    return 1;
  }
  return 0;
}

//#else
//
//void awslc_set_service_indicator_approved(void) {}
//
//void awslc_set_service_indicator_not_approved(void) {}
//
//#endif // defined(BORINGSSL_FIPS)
// end experiment
