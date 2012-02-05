/* -------------------------------------------------------------------------- *
 * file:	serial.c                                                      *
 * purpose:	provide management functions for serial numbers and file      *
 * ---------------------------------------------------------------------------*/
#include <string.h>
#include <openssl/x509.h>
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
     printf("Error: Can't open new file bio.");
     goto err;
  }

  if (BIO_read_filename(in,serialfile) <= 0) {
     if (!create) {
        printf(serialfile);
        goto err;
     }
     else {
        ret=BN_new();
        if (ret == NULL || !rand_serial(ret, ai))
            printf("Error: BN_new() Out of memory\n");
     }
  }
  else {
     if (!a2i_ASN1_INTEGER(in,ai,buf,1024)) {
        printf("Error: unable to load number from serial file.");
        goto err;
     }
     ret=ASN1_INTEGER_to_BN(ai,NULL);
     if (ret == NULL) {
        printf("Error: converting number from bin to BIGNUM");
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
     printf("Error: File name too long.");
     goto err;
   }

   if (suffix == NULL) BUF_strlcpy(buf[0], serialfile, BSIZE);
   else {
      j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);
   }
   out=BIO_new(BIO_s_file());
   if (out == NULL) {
      printf("Error: Can't create serial file.");
      goto err;
   }
   if (BIO_write_filename(out,buf[0]) <= 0) {
       printf("Error: Can't write serial file.");
       goto err;
   }

  if ((ai=BN_to_ASN1_INTEGER(serial,NULL)) == NULL) {
     printf("Error: converting serial to ASN.1 format");
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


ASN1_INTEGER * x509_load_serial(char *CAfile, char *serialfile, int create) {
    char *buf = NULL, *p;
    ASN1_INTEGER *bs = NULL;
    BIGNUM *serial = NULL;
    size_t len;
 
    len = ((serialfile == NULL)
          ?(strlen(CAfile)+strlen(POSTFIX)+1)
          :(strlen(serialfile)))+1;
 
    buf=OPENSSL_malloc(len);
    if (buf == NULL) {
       printf("Error: OpenSSL_malloc out of mem\n");
       goto end; 
    }
    if (serialfile == NULL) {
       BUF_strlcpy(buf,CAfile,len);
       for (p=buf; *p; p++)
           if (*p == '.') {
              *p='\0';
              break;
           }
       BUF_strlcat(buf,POSTFIX,len);
   }
   else
     BUF_strlcpy(buf,serialfile,len);
 
   serial = load_serial(buf, create, NULL);
   if (serial == NULL) goto end;
 
   if (!BN_add_word(serial,1)) {
      printf("Error: BN_add_word() failure\n");
      goto end;
   }
  if (!save_serial(buf, NULL, serial, &bs)) goto end;

 end:
   if (buf) OPENSSL_free(buf);
   BN_free(serial);
   return bs;
}
