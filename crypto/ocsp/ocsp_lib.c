// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ocsp_internal.h"


int OCSP_id_issuer_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)
{
  if (a == NULL || b == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  int ret = OBJ_cmp(a->hashAlgorithm->algorithm, b->hashAlgorithm->algorithm);
  if (ret != 0) return ret;
  ret = ASN1_OCTET_STRING_cmp(a->issuerNameHash, b->issuerNameHash);
  if (ret != 0) return ret;
  ret = ASN1_OCTET_STRING_cmp(a->issuerKeyHash, b->issuerKeyHash);
  return ret;
}

int OCSP_id_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)
{
  if (a == NULL || b == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  int ret = OCSP_id_issuer_cmp(a, b);
  if (ret != 0) return ret;
  ret = ASN1_INTEGER_cmp(a->serialNumber, b->serialNumber);
  return ret;
}
