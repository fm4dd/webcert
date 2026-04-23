/* ---------------------------------------------------------- *
 * file:	serial.c                                      *
 * purpose:	provide functions for serial numbers and file *
 *                                                            *
 * functions come from OpenSSL source x509.c, ca.c and apps.c *
 * -----------------------------------------------------------*/
#include <string.h>
#include <errno.h>
#include <openssl/buffer.h>
#include "webcert.h"

#define SERIAL_RAND_BITS 64
#define BSIZE		256

/* ---------------------------------------------------------- *
 * rand_serial(): create random serial number (not yet used)  *
 * returns  1 on success, and 0 for failure                   *
 * ---------------------------------------------------------- */
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai) {
  BIGNUM *btmp;

  if (b) btmp = b;
  else btmp = BN_new();

  if (!btmp) return 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  // OpenSSL v3.0 now uses BN_rand():
  // https://www.openssl.org/docs/manmaster/man7/migration_guide.html
  if (!BN_rand(btmp, SERIAL_RAND_BITS, 0, 0)) goto err;
#else
  if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0)) goto err;
#endif

  if (ai && !BN_to_ASN1_INTEGER(btmp, ai)) goto err;

  return 1;

err:
  if (!b) BN_free(btmp);
  return 0;
}

/* ---------------------------------------------------------- *
 * load_serial(): loads the serial number from a text file    *
 * Returns the serial as a BIGNUM object, or NULL for errors. *
 * ---------------------------------------------------------- */
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
      if((ret=BN_new()) == NULL)
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

/* ---------------------------------------------------------- *
 * save_serial(): writes a serial number back to text file    *
 * returns 1 for sucess, and 0 for error.                     *
 * ---------------------------------------------------------- */
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
