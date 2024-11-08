// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/pkcs7.h>

#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "internal.h"

#define MAX_SMLEN 1024

typedef struct mime_param_st {
    char *param_name;           /* Param name e.g. "micalg" */
    char *param_value;          /* Param value e.g. "sha1" */
} MIME_PARAM;

typedef struct mime_header_st {
    char *name;                 /* Name of line e.g. "content-type" */
    char *value;                /* Value of line e.g. "text/plain" */
    STACK_OF(MIME_PARAM) *params; /* Zero or more parameters */
} MIME_HEADER;

DEFINE_STACK_OF(MIME_PARAM)
DEFINE_STACK_OF(MIME_HEADER)

static MIME_HEADER *mime_hdr_find(STACK_OF(MIME_HEADER) *hdrs, const char *name)
{
    MIME_HEADER htmp;
    int idx;

    htmp.name = (char *)name;
    htmp.value = NULL;
    htmp.params = NULL;

    idx = sk_MIME_HEADER_find(hdrs, &htmp);
    return sk_MIME_HEADER_value(hdrs, idx);
}

static MIME_PARAM *mime_param_find(MIME_HEADER *hdr, const char *name)
{
    MIME_PARAM param;
    int idx;

    param.param_name = (char *)name;
    param.param_value = NULL;
    idx = sk_MIME_PARAM_find(hdr->params, &param);
    return sk_MIME_PARAM_value(hdr->params, idx);
}

static int mime_hdr_addparam(MIME_HEADER *mhdr, const char *name, const char *value) {
  char *tmpname = NULL, *tmpval = NULL, *p;
  MIME_PARAM *mparam = NULL;

  if (name) {
    tmpname = OPENSSL_strdup(name);
    if (!tmpname)
      goto err;
    for (p = tmpname; *p; p++)
      *p = OPENSSL_tolower(*p);
  }
  if (value) {
    tmpval = OPENSSL_strdup(value);
    if (!tmpval)
      goto err;
  }
  /* Parameter values are case sensitive so leave as is */
  mparam = OPENSSL_malloc(sizeof(*mparam));
  if (mparam == NULL)
    goto err;
  mparam->param_name = tmpname;
  mparam->param_value = tmpval;
  if (!sk_MIME_PARAM_push(mhdr->params, mparam))
    goto err;
  return 1;
err:
  OPENSSL_free(tmpname);
  OPENSSL_free(tmpval);
  OPENSSL_free(mparam);
  return 0;
}

static int mime_hdr_cmp(const MIME_HEADER *const *a,
                        const MIME_HEADER *const *b) {
  if (!(*a)->name || !(*b)->name)
    return !!(*a)->name - !!(*b)->name;

  return strcmp((*a)->name, (*b)->name);
}

static int mime_param_cmp(const MIME_PARAM *const *a,
                          const MIME_PARAM *const *b) {
  if (!(*a)->param_name || !(*b)->param_name)
    return !!(*a)->param_name - !!(*b)->param_name;
  return strcmp((*a)->param_name, (*b)->param_name);
}

static void mime_param_free(MIME_PARAM *param)
{
    OPENSSL_free(param->param_name);
    OPENSSL_free(param->param_value);
    OPENSSL_free(param);
}

static MIME_HEADER *mime_hdr_new(const char *name, const char *value)
{
    MIME_HEADER *mhdr = NULL;
    char *tmpname = NULL, *tmpval = NULL, *p;

    if (name) {
        if ((tmpname = OPENSSL_strdup(name)) == NULL)
            return NULL;
        for (p = tmpname; *p; p++)
            *p = OPENSSL_tolower(*p);
    }
    if (value) {
        if ((tmpval = OPENSSL_strdup(value)) == NULL)
            goto err;
        for (p = tmpval; *p; p++)
            *p = OPENSSL_tolower(*p);
    }
    mhdr = OPENSSL_malloc(sizeof(*mhdr));
    if (mhdr == NULL)
        goto err;
    mhdr->name = tmpname;
    mhdr->value = tmpval;
    if ((mhdr->params = sk_MIME_PARAM_new(mime_param_cmp)) == NULL)
        goto err;
    return mhdr;

 err:
    OPENSSL_free(tmpname);
    OPENSSL_free(tmpval);
    OPENSSL_free(mhdr);
    return NULL;
}

static void mime_hdr_free(MIME_HEADER *hdr)
{
    if (hdr == NULL)
        return;
    OPENSSL_free(hdr->name);
    OPENSSL_free(hdr->value);
    if (hdr->params)
        sk_MIME_PARAM_pop_free(hdr->params, mime_param_free);
    OPENSSL_free(hdr);
}

/*-
 * Check for a multipart boundary. Returns:
 * 0 : no boundary
 * 1 : part boundary
 * 2 : final boundary
 */
static int mime_bound_check(char *line, int linelen, const char *bound, int blen) {
  if (linelen == -1)
    linelen = strlen(line);
  if (blen == -1)
    blen = strlen(bound);
  /* Quickly eliminate if line length too short */
  if (blen + 2 > linelen)
    return 0;
  /* Check for part boundary */
  if ((strncmp(line, "--", 2) == 0) && strncmp(line + 2, bound, blen) == 0) {
    if (strncmp(line + blen + 2, "--", 2) == 0)
      return 2;
    else
      return 1;
  }
  return 0;
}

static int strip_eol(char *linebuf, int *plen, int flags) {
  int len = *plen;
  char *p, c;
  int is_eol = 0;

  for (p = linebuf + len - 1; len > 0; len--, p--) {
    c = *p;
    if (c == '\n') {
      is_eol = 1;
    // This checks for |SMIME_ASCIICRLF|, but it's not used in Ruby.
//    } else if (is_eol && flags & SMIME_ASCIICRLF && c == 32) {
//      /* Strip trailing space on a line; 32 == ASCII for ' ' */
//      continue;
    } else if (c != '\r') {
      break;
    }
  }
  *plen = len;
  return is_eol;
}

#define MIME_INVALID    0
#define MIME_START      1
#define MIME_TYPE       2
#define MIME_NAME       3
#define MIME_VALUE      4
#define MIME_QUOTE      5
#define MIME_COMMENT    6

/* Strip a parameter of whitespace from start of param */
static char *strip_start(char *name)
{
    char *p, c;
    /* Look for first non white space or quote */
    for (p = name; (c = *p); p++) {
        if (c == '"') {
            /* Next char is start of string if non null */
            if (p[1])
                return p + 1;
            /* Else null string */
            return NULL;
        }
        if (!OPENSSL_isspace(c))
            return p;
    }
    return NULL;
}

/* As above but strip from end of string : maybe should handle brackets? */
static char *strip_end(char *name) {
  char *p, c;
  if (!name)
    return NULL;
  /* Look for first non white space or quote */
  for (p = name + strlen(name) - 1; p >= name; p--) {
    c = *p;
    if (c == '"') {
      if (p - 1 == name)
        return NULL;
      *p = 0;
      return name;
    }
    if (OPENSSL_isspace(c))
      *p = 0;
    else
      return name;
  }
  return NULL;
}

static char *strip_ends(char *name) { return strip_end(strip_start(name)); }

static int multi_split(BIO *bio, const char *bound, STACK_OF(BIO) **ret)
{
    char linebuf[MAX_SMLEN];
    int len, blen;
    int eol = 0, next_eol = 0;
    BIO *bpart = NULL;
    STACK_OF(BIO) *parts;
    char state, part, first;

    blen = strlen(bound);
    part = 0;
    state = 0;
    first = 1;
    parts = sk_BIO_new_null();
    *ret = parts;
    if (*ret == NULL)
        return 0;
    while ((len = BIO_gets(bio, linebuf, MAX_SMLEN)) > 0) {
        state = mime_bound_check(linebuf, len, bound, blen);
        if (state == 1) {
            first = 1;
            part++;
        } else if (state == 2) {
            if (!sk_BIO_push(parts, bpart)) {
                BIO_free(bpart);
                return 0;
            }
            return 1;
        } else if (part) {
            /* Strip CR+LF from linebuf */
            next_eol = strip_eol(linebuf, &len, 0);
            if (first) {
                first = 0;
                if (bpart)
                    if (!sk_BIO_push(parts, bpart)) {
                        BIO_free(bpart);
                        return 0;
                    }
                bpart = BIO_new(BIO_s_mem());
                if (bpart == NULL)
                    return 0;
                BIO_set_mem_eof_return(bpart, 0);
            } else if (eol)
                BIO_write(bpart, "\r\n", 2);
            eol = next_eol;
            if (len)
                BIO_write(bpart, linebuf, len);
        }
    }
    BIO_free(bpart);
    return 0;
}

static STACK_OF(MIME_HEADER) *mime_parse_hdr(BIO *bio) {
  char *p, *q, c;
  char *ntmp;
  char linebuf[MAX_SMLEN];
  MIME_HEADER *mhdr = NULL, *new_hdr = NULL;
  STACK_OF(MIME_HEADER) *headers;
  int len, state, save_state = 0;

  headers = sk_MIME_HEADER_new(mime_hdr_cmp);
  if (headers == NULL)
    return NULL;
  while ((len = BIO_gets(bio, linebuf, MAX_SMLEN)) > 0) {
    /* If whitespace at line start then continuation line */
    if (mhdr && OPENSSL_isspace(linebuf[0]))
      state = MIME_NAME;
    else
      state = MIME_START;
    ntmp = NULL;
    /* Go through all characters */
    for (p = linebuf, q = linebuf; (c = *p) && (c != '\r') && (c != '\n');
         p++) {
      /*
             * State machine to handle MIME headers if this looks horrible
             * that's because it *is*
       */

      switch (state) {
        case MIME_START:
          if (c == ':') {
            state = MIME_TYPE;
            *p = 0;
            ntmp = strip_ends(q);
            q = p + 1;
          }
          break;

        case MIME_TYPE:
          if (c == ';') {
            //                    mime_debug("Found End Value\n");
            *p = 0;
            new_hdr = mime_hdr_new(ntmp, strip_ends(q));
            if (new_hdr == NULL)
              goto err;
            if (!sk_MIME_HEADER_push(headers, new_hdr))
              goto err;
            mhdr = new_hdr;
            new_hdr = NULL;
            ntmp = NULL;
            q = p + 1;
            state = MIME_NAME;
          } else if (c == '(') {
            save_state = state;
            state = MIME_COMMENT;
          }
          break;

        case MIME_COMMENT:
          if (c == ')') {
            state = save_state;
          }
          break;

        case MIME_NAME:
          if (c == '=') {
            state = MIME_VALUE;
            *p = 0;
            ntmp = strip_ends(q);
            q = p + 1;
          }
          break;

        case MIME_VALUE:
          if (c == ';') {
            state = MIME_NAME;
            *p = 0;
            mime_hdr_addparam(mhdr, ntmp, strip_ends(q));
            ntmp = NULL;
            q = p + 1;
          } else if (c == '"') {
            //                    mime_debug("Found Quote\n");
            state = MIME_QUOTE;
          } else if (c == '(') {
            save_state = state;
            state = MIME_COMMENT;
          }
          break;

        case MIME_QUOTE:
          if (c == '"') {
            //                    mime_debug("Found Match Quote\n");
            state = MIME_VALUE;
          }
          break;
      }
    }

    if (state == MIME_TYPE) {
      new_hdr = mime_hdr_new(ntmp, strip_ends(q));
      if (new_hdr == NULL)
        goto err;
      if (!sk_MIME_HEADER_push(headers, new_hdr))
        goto err;
      mhdr = new_hdr;
      new_hdr = NULL;
    } else if (state == MIME_VALUE)
      mime_hdr_addparam(mhdr, ntmp, strip_ends(q));
    if (p == linebuf)
      break; /* Blank line means end of headers */
  }

  return headers;

err:
  mime_hdr_free(new_hdr);
  sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
  return NULL;
}

static ASN1_VALUE *b64_read_asn1(BIO *bio, const ASN1_ITEM *it) {
  BIO *b64;
  ASN1_VALUE *val;

  if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
    OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  bio = BIO_push(b64, bio);
  val = ASN1_item_d2i_bio(it, bio, NULL);
  if (!val) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_DECODE_ERROR);
  }
  (void)BIO_flush(bio);
  BIO_pop(bio);
  BIO_free(b64);
  return val;
}

static ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it) {
  BIO *asnin;
  STACK_OF(MIME_HEADER) *headers = NULL;
  STACK_OF(BIO) *parts = NULL;
  MIME_HEADER *hdr;
  MIME_PARAM *prm;
  ASN1_VALUE *val;
  int ret;

  if (bcont)
    *bcont = NULL;

  if ((headers = mime_parse_hdr(bio)) == NULL) {
//    ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_MIME_PARSE_ERROR);
    return NULL;
  }

  if ((hdr = mime_hdr_find(headers, "content-type")) == NULL ||
      hdr->value == NULL) {
    sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
//    ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_NO_CONTENT_TYPE);
    return NULL;
  }

  /* Handle multipart/signed */

  if (strcmp(hdr->value, "multipart/signed") == 0) {
    /* Split into two parts */
    prm = mime_param_find(hdr, "boundary");
    if (!prm || !prm->param_value) {
      sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
//      ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_NO_MULTIPART_BOUNDARY);
      return NULL;
    }
    ret = multi_split(bio, prm->param_value, &parts);
    sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
    if (!ret || (sk_BIO_num(parts) != 2)) {
//      ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_NO_MULTIPART_BODY_FAILURE);
      sk_BIO_pop_free(parts, BIO_vfree);
      return NULL;
    }

    /* Parse the signature piece */
    asnin = sk_BIO_value(parts, 1);

    if ((headers = mime_parse_hdr(asnin)) == NULL) {
//      ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_MIME_SIG_PARSE_ERROR);
      sk_BIO_pop_free(parts, BIO_vfree);
      return NULL;
    }

    /* Get content type */

    if ((hdr = mime_hdr_find(headers, "content-type")) == NULL ||
        hdr->value == NULL) {
      sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
//      ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_NO_SIG_CONTENT_TYPE);
      sk_BIO_pop_free(parts, BIO_vfree);
      return NULL;
    }

    if (strcmp(hdr->value, "application/x-pkcs7-signature") &&
        strcmp(hdr->value, "application/pkcs7-signature")) {
//      ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_SIG_INVALID_MIME_TYPE);
      ERR_add_error_data(2, "type: ", hdr->value);
      sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
      sk_BIO_pop_free(parts, BIO_vfree);
      return NULL;
    }
    sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
    /* Read in ASN1 */
    if ((val = b64_read_asn1(asnin, it)) == NULL) {
//      ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_ASN1_SIG_PARSE_ERROR);
      sk_BIO_pop_free(parts, BIO_vfree);
      return NULL;
    }

    if (bcont) {
      *bcont = sk_BIO_value(parts, 0);
      BIO_free(asnin);
      sk_BIO_free(parts);
    } else
      sk_BIO_pop_free(parts, BIO_vfree);
    return val;
  }

  /* OK, if not multipart/signed try opaque signature */

  if (strcmp(hdr->value, "application/x-pkcs7-mime") &&
      strcmp(hdr->value, "application/pkcs7-mime")) {
//    ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_INVALID_MIME_TYPE);
    ERR_add_error_data(2, "type: ", hdr->value);
    sk_MIME_HEADER_pop_free(headers, mime_hdr_free);
    return NULL;
  }

  sk_MIME_HEADER_pop_free(headers, mime_hdr_free);

  if ((val = b64_read_asn1(bio, it)) == NULL) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_DECODE_ERROR);
//    ASN1err(ASN1_F_SMIME_READ_ASN1, ASN1_R_ASN1_PARSE_ERROR);
    return NULL;
  }
  return val;
}

PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont) {
  return (PKCS7 *)SMIME_read_ASN1(bio, bcont, ASN1_ITEM_rptr(PKCS7));
}
