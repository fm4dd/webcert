/* -------------------------------------------------------------------------- *
 * file:	serial.c                                                      *
 * purpose:	provide management functions for serial numbers and file      *
 * ---------------------------------------------------------------------------*/
#include <string.h>
#include <openssl/buffer.h>
#include "webcert.h"

#define POSTFIX		".srl"
#define SERIAL_RAND_BITS 64
#define BSIZE		256

/* the functions below were taken from OpenSSL source x509.c and apps.c */

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai) {
   BIGNUM *btmp;
   int ret = 0;

   if (b) btmp = b;
   else btmp = BN_new();

   if (!btmp) return 0;

   if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0)) goto error;
   if (ai && !BN_to_ASN1_INTEGER(btmp, ai)) goto error;

   ret = 1;

   error:
      if (!b) BN_free(btmp);
      return ret;
}


BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai) {
  BIO *in=NULL;
  BIGNUM *ret=NULL;
  char buf[1024];
  ASN1_INTEGER *ai=NULL;

  ai=ASN1_INTEGER_new();
  if (ai == NULL) goto err;

  if ((in=BIO_new(BIO_s_file())) == NULL) {
     int_error("Error: Can't open new file bio.");
     goto err;
  }

  if (BIO_read_filename(in,serialfile) <= 0) {
     if (!create) {
        int_error(serialfile);
        goto err;
     }
     else {
        ret=BN_new();
        if (ret == NULL || !rand_serial(ret, ai))
            int_error("Error: BN_new() Out of memory\n");
     }
  }
  else {
     if (!a2i_ASN1_INTEGER(in,ai,buf,1024)) {
        int_error("Error: unable to load number from serial file.");
        goto err;
     }
     ret=ASN1_INTEGER_to_BN(ai,NULL);
     if (ret == NULL) {
        int_error("Error: converting number from bin to BIGNUM");
        goto err;
     }
  }

  if (ret && retai) {
     *retai = ai;
     ai = NULL;
  }
  err:
    if (in != NULL) BIO_free(in);
    if (ai != NULL) ASN1_INTEGER_free(ai);
    return(ret);
}

int save_serial(char *serialfile, char *suffix, BIGNUM *serial,
                                                ASN1_INTEGER **retai) {
  char buf[1][BSIZE];
  BIO *out = NULL;
  int ret=0;
  ASN1_INTEGER *ai=NULL;
  int j;

  if (suffix == NULL) j = strlen(serialfile);
  else j = strlen(serialfile) + strlen(suffix) + 1;
  if (j >= BSIZE) {
     int_error("Error: File name too long.");
     goto err;
   }

   if (suffix == NULL) BUF_strlcpy(buf[0], serialfile, BSIZE);
   else {
      j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);
   }
   out=BIO_new(BIO_s_file());
   if (out == NULL) {
      int_error("Error: Can't create serial file.");
      goto err;
   }
   if (BIO_write_filename(out,buf[0]) <= 0) {
       int_error("Error: Can't write serial file.");
       goto err;
   }

  if ((ai=BN_to_ASN1_INTEGER(serial,NULL)) == NULL) {
     int_error("Error: converting serial to ASN.1 format");
     goto err;
  }
  i2a_ASN1_INTEGER(out,ai);
  BIO_puts(out,"\n");
  ret=1;
  if (retai) {
     *retai = ai;
     ai = NULL;
  }
err:
    if (out != NULL) BIO_free_all(out);
    if (ai != NULL) ASN1_INTEGER_free(ai);
  return(ret);
}
