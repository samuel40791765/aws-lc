/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// OCSP ASN1 structure definitions can be found in RFC link below
// https://tools.ietf.org/html/rfc6960#section-4.2.1

#include <openssl/mem.h>

#include "internal.h"
#include "../internal.h"


ASN1_SEQUENCE(OCSP_CERTID) = {
    ASN1_SIMPLE(OCSP_CERTID, hashAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(OCSP_CERTID, issuerNameHash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(OCSP_CERTID, issuerKeyHash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(OCSP_CERTID, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(OCSP_CERTID)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_CERTID)

//ASN1_SEQUENCE(OCSP_RESPBYTES) = {
//    ASN1_SIMPLE(OCSP_RESPBYTES, responseType, ASN1_OBJECT),
//    ASN1_SIMPLE(OCSP_RESPBYTES, response, ASN1_OCTET_STRING)
//} ASN1_SEQUENCE_END(OCSP_RESPBYTES)
//
//IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPBYTES)

//ASN1_SEQUENCE(OCSP_RESPONSE) = {
//    ASN1_SIMPLE(OCSP_RESPONSE, responseStatus, ASN1_ENUMERATED),
//    ASN1_EXP_OPT(OCSP_RESPONSE, responseBytes, OCSP_RESPBYTES, 0)
//} ASN1_SEQUENCE_END(OCSP_RESPONSE)

//IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPONSE)

OCSP_RESPONSE *OCSP_RESPONSE_new(void) {
  OCSP_RESPONSE *ret;

  ret = OPENSSL_malloc(sizeof(OCSP_RESPONSE));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(OCSP_RESPONSE));
  return ret;
}

void OCSP_RESPONSE_free(OCSP_RESPONSE *resp) {
  if (resp == NULL) {
    return;
  }
  OPENSSL_free(resp);
}

OCSP_RESPONSE *d2i_OCSP_RESPONSE(OCSP_RESPONSE **out,
                                        const uint8_t **inp, long len) {
  OCSP_RESPONSE *ret = OCSP_RESPONSE_new();
  if (ret == NULL) {
    goto err;
  }
  CBS cbs, ocspResponse, responseStatus;
  CBS_init(&cbs, *inp, (size_t)len);
  if (!CBS_get_asn1(&cbs, &ocspResponse, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&ocspResponse, &responseStatus, CBS_ASN1_ENUMERATED) ||
      !CBS_get_u8(&responseStatus, &ret->responseStatus)) {
    OPENSSL_PUT_ERROR(OCSP, ASN1_R_DECODE_ERROR);
    goto err;
  }
  fprintf(stderr, "out: %hu\n", ret->responseStatus);
  fprintf(stderr, "len: %lu\n", CBS_len(&ocspResponse));

  if(CBS_len(&ocspResponse) > 0) {
    const uint8_t *input = CBS_data(&ocspResponse);
    ret->responseBytes = d2i_OCSP_RESPBYTES(NULL, &input, (long)CBS_len(&ocspResponse));
    if (!ret->responseBytes) {
      OPENSSL_PUT_ERROR(OCSP, ASN1_R_DECODE_ERROR);
      return 0;
    }
  }

  if(out) {
    *out = ret;
  }
  *inp = CBS_data(&cbs);
  return ret;
err:
  OCSP_RESPONSE_free(ret);
  *inp = CBS_data(&cbs);
  return NULL;
}

OCSP_RESPBYTES *OCSP_RESPBYTES_new(void) {
  OCSP_RESPBYTES *ret;

  ret = OPENSSL_malloc(sizeof(OCSP_RESPBYTES));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(OCSP_RESPBYTES));
  return ret;
}

void OCSP_RESPBYTES_free(OCSP_RESPBYTES *resp) {
  if (resp == NULL) {
    return;
  }
  OPENSSL_free(resp);
}

OCSP_RESPBYTES *d2i_OCSP_RESPBYTES(OCSP_RESPBYTES **out,
                                        const uint8_t **inp, long len) {
  CBS cbs, respBytes, respType, response;
  CBS_init(&cbs, *inp, (size_t)len);
  fprintf(stderr, "len: %lu\n", CBS_len(&cbs));
  if(!CBS_get_asn1(&cbs, &respBytes, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&respBytes, &respType, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&respBytes, &response, CBS_ASN1_OCTETSTRING)){
    fprintf(stderr, "respbytes len: %lu\n", CBS_len(&respBytes));
    fprintf(stderr, "oid len: %lu\n", CBS_len(&respType));
    fprintf(stderr, "response len: %lu\n", CBS_len(&response));
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }
//  if(responseBytesPresent) {
//    fprintf(stderr, "test\n");
//    if (!CBS_get_asn1(&respBytes, &oid, CBS_ASN1_OBJECT) ||
//        !CBS_get_asn1(&respBytes, &response, CBS_ASN1_OCTETSTRING) ||
//        CBS_len(&oid) != 0) {
//      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
//      return NULL;
//    }
//  }

  OCSP_RESPBYTES *ret = OCSP_RESPBYTES_new();
  if (ret == NULL) {
    goto err;
  }
  ret->nid = OBJ_cbs2nid(&respType);
  ret->response_data = CBS_data(&response);
  ret->response_len = CBS_len(&response);

  if(out) {
    *out = ret;
  }
  *inp = CBS_data(&cbs);
  return ret;

err:
  OCSP_RESPBYTES_free(ret);
  *inp = CBS_data(&cbs);
  return NULL;
}

ASN1_CHOICE(OCSP_RESPID) = {
    ASN1_EXP(OCSP_RESPID, value.byName, X509_NAME, 1),
    ASN1_EXP(OCSP_RESPID, value.byKey, ASN1_OCTET_STRING, 2)
} ASN1_CHOICE_END(OCSP_RESPID)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPID)

ASN1_SEQUENCE(OCSP_REVOKEDINFO) = {
    ASN1_SIMPLE(OCSP_REVOKEDINFO, revocationTime, ASN1_GENERALIZEDTIME),
    ASN1_EXP_OPT(OCSP_REVOKEDINFO, revocationReason, ASN1_ENUMERATED, 0)
} ASN1_SEQUENCE_END(OCSP_REVOKEDINFO)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_REVOKEDINFO)

ASN1_CHOICE(OCSP_CERTSTATUS) = {
    ASN1_IMP(OCSP_CERTSTATUS, value.good, ASN1_NULL, 0),
    ASN1_IMP(OCSP_CERTSTATUS, value.revoked, OCSP_REVOKEDINFO, 1),
    ASN1_IMP(OCSP_CERTSTATUS, value.unknown, ASN1_NULL, 2)
} ASN1_CHOICE_END(OCSP_CERTSTATUS)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_CERTSTATUS)

ASN1_SEQUENCE(OCSP_SINGLERESP) = {
    ASN1_SIMPLE(OCSP_SINGLERESP, certId, OCSP_CERTID),
    ASN1_SIMPLE(OCSP_SINGLERESP, certStatus, OCSP_CERTSTATUS),
    ASN1_SIMPLE(OCSP_SINGLERESP, thisUpdate, ASN1_GENERALIZEDTIME),
    ASN1_EXP_OPT(OCSP_SINGLERESP, nextUpdate, ASN1_GENERALIZEDTIME, 0),
    ASN1_EXP_SEQUENCE_OF_OPT(OCSP_SINGLERESP, singleExtensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(OCSP_SINGLERESP)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_SINGLERESP)

ASN1_SEQUENCE(OCSP_RESPDATA) = {
    ASN1_EXP_OPT(OCSP_RESPDATA, version, ASN1_INTEGER, 0),
    ASN1_SIMPLE(OCSP_RESPDATA, responderId, OCSP_RESPID),
    ASN1_SIMPLE(OCSP_RESPDATA, producedAt, ASN1_GENERALIZEDTIME),
    ASN1_SEQUENCE_OF(OCSP_RESPDATA, responses, OCSP_SINGLERESP),
    ASN1_EXP_SEQUENCE_OF_OPT(OCSP_RESPDATA, responseExtensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(OCSP_RESPDATA)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPDATA)

ASN1_SEQUENCE(OCSP_BASICRESP) = {
    ASN1_SIMPLE(OCSP_BASICRESP, tbsResponseData, OCSP_RESPDATA),
    ASN1_SIMPLE(OCSP_BASICRESP, signatureAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(OCSP_BASICRESP, signature, ASN1_BIT_STRING),
    ASN1_EXP_SEQUENCE_OF_OPT(OCSP_BASICRESP, certs, X509, 0)
} ASN1_SEQUENCE_END(OCSP_BASICRESP)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_BASICRESP)
