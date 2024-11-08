// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/pkcs7.h>

#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/obj.h>
#include <openssl/rand.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "internal.h"

#define MAX_SMLEN 1024


# define SMIME_OLDMIME           0x400
# define SMIME_CRLFEOL           0x800
# define SMIME_STREAM            0x1000

/* Base 64 read and write of ASN1 structure */

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

/* Copy text from one BIO to another making the output CRLF at EOL */
static int SMIME_crlf_copy(BIO *in, BIO *out, int flags)
{
    BIO *bf;
    char eol;
    int len;
    char linebuf[MAX_SMLEN];
    int ret;
    /*
     * Buffer output so we don't write one line at a time. This is useful
     * when streaming as we don't end up with one OCTET STRING per line.
     */
    // Uses |BIO_f_buffer|, need to replace with something else
    bf = BIO_new(BIO_f_base64());
    if (bf == NULL)
        return 0;
    out = BIO_push(bf, out);
    if (flags & SMIME_BINARY) {
        while ((len = BIO_read(in, linebuf, MAX_SMLEN)) > 0)
            BIO_write(out, linebuf, len);
    } else {
        int eolcnt = 0;
        if (flags & SMIME_TEXT)
            BIO_printf(out, "Content-Type: text/plain\r\n\r\n");
        while ((len = BIO_gets(in, linebuf, MAX_SMLEN)) > 0) {
            eol = strip_eol(linebuf, &len, flags);
            if (len) {
                /* Not EOF: write out all CRLF */
                if (flags & SMIME_ASCIICRLF) {
                    int i;
                    for (i = 0; i < eolcnt; i++)
                        BIO_write(out, "\r\n", 2);
                    eolcnt = 0;
                }
                BIO_write(out, linebuf, len);
                if (eol)
                    BIO_write(out, "\r\n", 2);
            } else if (flags & SMIME_ASCIICRLF)
                eolcnt++;
            else if (eol)
                BIO_write(out, "\r\n", 2);
        }
    }
    ret = BIO_flush(out);
    BIO_pop(out);
    BIO_free(bf);
    if (ret <= 0)
        return 0;

    return 1;
}

static int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
                        const ASN1_ITEM *it)
{
    /* If streaming create stream BIO and copy all content through it */
    if (flags & SMIME_STREAM) {
        BIO *bio, *tbio;

        // This below will be very hard to support
        // https://github.com/openssl/openssl/blob/master/crypto/asn1/bio_ndef.c#L58
        bio = BIO_new_NDEF(out, val, it);
        if (!bio) {
            ASN1err(ASN1_F_I2D_ASN1_BIO_STREAM, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        SMIME_crlf_copy(in, bio, flags);
        (void)BIO_flush(bio);
        /* Free up successive BIOs until we hit the old output BIO */
        do {
            tbio = BIO_pop(bio);
            BIO_free(bio);
            bio = tbio;
        } while (bio != out);
    }
    /*
     * else just write out ASN1 structure which will have all content stored
     * internally
     */
    else
        ASN1_item_i2d_bio(it, out, val);
    return 1;
}

static int B64_write_ASN1(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
                          const ASN1_ITEM *it) {
  BIO *b64;
  int r;
  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    //        ERR_raise(ERR_LIB_ASN1, ERR_R_BIO_LIB);
    return 0;
  }
  /*
     * prepend the b64 BIO so all data is base64 encoded.
   */
  out = BIO_push(b64, out);
  r = i2d_ASN1_bio_stream(out, val, in, flags, it);
  (void)BIO_flush(out);
  BIO_pop(out);
  BIO_free(b64);
  return r;
}

static int asn1_write_micalg(BIO *out, STACK_OF(X509_ALGOR) *mdalgs) {
  const EVP_MD *md;
  int have_unknown = 0, write_comma, ret = 0, md_nid;
  have_unknown = 0;
  write_comma = 0;
  for (size_t i = 0; i < sk_X509_ALGOR_num(mdalgs); i++) {
    if (write_comma)
      BIO_write(out, ",", 1);
    write_comma = 1;
    md_nid = OBJ_obj2nid(sk_X509_ALGOR_value(mdalgs, i)->algorithm);
    md = EVP_get_digestbynid(md_nid);
    if (md && md->md_ctrl) {
      int rv;
      char *micstr;
      // What is this below??
      // https://github.com/openssl/openssl/blob/master/crypto/evp/digest.c#L894
      rv = md->md_ctrl(NULL, EVP_MD_CTRL_MICALG, 0, &micstr);
      if (rv > 0) {
        BIO_puts(out, micstr);
        OPENSSL_free(micstr);
        continue;
      }
      if (rv != -2)
        goto err;
    }
    switch (md_nid) {
      case NID_sha1:
        BIO_puts(out, "sha1");
        break;
      case NID_md5:
        BIO_puts(out, "md5");
        break;
      case NID_sha256:
        BIO_puts(out, "sha-256");
        break;
      case NID_sha384:
        BIO_puts(out, "sha-384");
        break;
      case NID_sha512:
        BIO_puts(out, "sha-512");
        break;
//
//      case NID_id_GostR3411_94:
//        BIO_puts(out, "gostr3411-94");
//        goto err;
//
//      case NID_id_GostR3411_2012_256:
//        BIO_puts(out, "gostr3411-2012-256");
//        goto err;
//
//      case NID_id_GostR3411_2012_512:
//        BIO_puts(out, "gostr3411-2012-512");
//        goto err;
      default:
        if (have_unknown)
          write_comma = 0;
        else {
          BIO_puts(out, "unknown");
          have_unknown = 1;
        }
        break;
    }
  }

  ret = 1;
err:

  return ret;
}

/* Handle output of ASN1 data */

typedef struct ASN1_STREAM_ARG_st {
    /* BIO to stream through */
    BIO *out;
    /* BIO with filters appended */
    BIO *ndef_bio;
    /* Streaming I/O boundary */
    unsigned char **boundary;
} ASN1_STREAM_ARG;

static int asn1_output_data(BIO *out, BIO *data, ASN1_VALUE *val, int flags,
                            const ASN1_ITEM *it)
{
    BIO *tmpbio;
    const ASN1_AUX *aux = it->funcs;
    ASN1_STREAM_ARG sarg;
    int rv = 1;

    /*
     * If data is not detached or resigning then the output BIO is already
     * set up to finalise when it is written through.
     */
    if (!(flags & SMIME_DETACHED) || (flags & PKCS7_REUSE_DIGEST)) {
        SMIME_crlf_copy(data, out, flags);
        return 1;
    }

    if (!aux || !aux->asn1_cb) {
        ASN1err(ASN1_F_ASN1_OUTPUT_DATA, ASN1_R_STREAMING_NOT_SUPPORTED);
        return 0;
    }

    sarg.out = out;
    sarg.ndef_bio = NULL;
    sarg.boundary = NULL;

    /* Let ASN1 code prepend any needed BIOs */

    if (aux->asn1_cb(ASN1_OP_DETACHED_PRE, &val, it, &sarg) <= 0)
        return 0;

    /* Copy data across, passing through filter BIOs for processing */
    SMIME_crlf_copy(data, sarg.ndef_bio, flags);

    /* Finalize structure */
    if (aux->asn1_cb(ASN1_OP_DETACHED_POST, &val, it, &sarg) <= 0)
        rv = 0;

    /* Now remove any digests prepended to the BIO */

    while (sarg.ndef_bio != out) {
        tmpbio = BIO_pop(sarg.ndef_bio);
        BIO_free(sarg.ndef_bio);
        sarg.ndef_bio = tmpbio;
    }

    return rv;

}

static int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
                     int ctype_nid, int econt_nid,
                     STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it)
{
    char bound[33], c;
    int i;
    const char *mime_prefix, *mime_eol, *cname = "smime.p7m";
    const char *msg_type = NULL;
    if (flags & SMIME_OLDMIME)
        mime_prefix = "application/x-pkcs7-";
    else
        mime_prefix = "application/pkcs7-";

    if (flags & SMIME_CRLFEOL)
        mime_eol = "\r\n";
    else
        mime_eol = "\n";
    if ((flags & PKCS7_DETACHED) && data) {
        /* We want multipart/signed */
        /* Generate a random boundary */
        if (RAND_bytes((unsigned char *)bound, 32) <= 0)
            return 0;
        for (i = 0; i < 32; i++) {
            c = bound[i] & 0xf;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;
            bound[i] = c;
        }
        bound[32] = 0;
        BIO_printf(bio, "MIME-Version: 1.0%s", mime_eol);
        BIO_printf(bio, "Content-Type: multipart/signed;");
        BIO_printf(bio, " protocol=\"%ssignature\";", mime_prefix);
        BIO_puts(bio, " micalg=\"");
        asn1_write_micalg(bio, mdalgs);
        BIO_printf(bio, "\"; boundary=\"----%s\"%s%s",
                   bound, mime_eol, mime_eol);
        BIO_printf(bio, "This is an S/MIME signed message%s%s",
                   mime_eol, mime_eol);
        /* Now write out the first part */
        BIO_printf(bio, "------%s%s", bound, mime_eol);
        if (!asn1_output_data(bio, data, val, flags, it))
            return 0;
        BIO_printf(bio, "%s------%s%s", mime_eol, bound, mime_eol);

        /* Headers for signature */

        BIO_printf(bio, "Content-Type: %ssignature;", mime_prefix);
        BIO_printf(bio, " name=\"smime.p7s\"%s", mime_eol);
        BIO_printf(bio, "Content-Transfer-Encoding: base64%s", mime_eol);
        BIO_printf(bio, "Content-Disposition: attachment;");
        BIO_printf(bio, " filename=\"smime.p7s\"%s%s", mime_eol, mime_eol);
        B64_write_ASN1(bio, val, NULL, 0, it);
        BIO_printf(bio, "%s------%s--%s%s", mime_eol, bound,
                   mime_eol, mime_eol);
        return 1;
    }

    /* Determine smime-type header */

    if (ctype_nid == NID_pkcs7_enveloped)
        msg_type = "enveloped-data";
    else if (ctype_nid == NID_pkcs7_signed) {
        if (econt_nid == NID_id_smime_ct_receipt)
            msg_type = "signed-receipt";
        else if (sk_X509_ALGOR_num(mdalgs) >= 0)
            msg_type = "signed-data";
        else
            msg_type = "certs-only";
    } else if (ctype_nid == NID_id_smime_ct_compressedData) {
        msg_type = "compressed-data";
        cname = "smime.p7z";
    }
    /* MIME headers */
    BIO_printf(bio, "MIME-Version: 1.0%s", mime_eol);
    BIO_printf(bio, "Content-Disposition: attachment;");
    BIO_printf(bio, " filename=\"%s\"%s", cname, mime_eol);
    BIO_printf(bio, "Content-Type: %smime;", mime_prefix);
    if (msg_type)
        BIO_printf(bio, " smime-type=%s;", msg_type);
    BIO_printf(bio, " name=\"%s\"%s", cname, mime_eol);
    BIO_printf(bio, "Content-Transfer-Encoding: base64%s%s",
               mime_eol, mime_eol);
    if (!B64_write_ASN1(bio, val, data, flags, it))
        return 0;
    BIO_printf(bio, "%s", mime_eol);
    return 1;
}

int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags) {
  STACK_OF(X509_ALGOR) *mdalgs;
  int ctype_nid = OBJ_obj2nid(p7->type);
  if (ctype_nid == NID_pkcs7_signed)
    mdalgs = p7->d.sign->md_algs;
  else
    mdalgs = NULL;

  flags ^= SMIME_OLDMIME;

  return SMIME_write_ASN1(bio, (ASN1_VALUE *)p7, data, flags, ctype_nid,
                          NID_undef, mdalgs, ASN1_ITEM_rptr(PKCS7));
}
