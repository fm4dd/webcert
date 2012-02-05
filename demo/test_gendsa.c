/* test_gendsa.c			25/06/2005 frank4dd	     */
/* test example for generating a dsa public/private key pair         */

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define KEYSIZE	1024

int main() {

  int ret=1;
  DSA *mydsa	=NULL;
  BIO *outbio	=NULL;
  const EVP_CIPHER *enc=NULL;


/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work. It is not well documented, I found out after looking into  *
 * the openssl source directly.                                               *
 * needed by: PEM_read_PrivateKey(), X509_REQ_verify() ...                    *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

   mydsa = DSA_new();

   mydsa = DSA_generate_parameters(KEYSIZE, NULL, 0, NULL, NULL, NULL, NULL);

   printf("Generating DSA key, %d bits\n", BN_num_bits(mydsa->p));

   if (! (DSA_generate_key(mydsa)))
      printf("error generating dsa key.\n");
   else { 

      outbio = BIO_new(BIO_s_file());
      BIO_set_fp(outbio, stdout, BIO_NOCLOSE);

      PEM_write_bio_DSAPrivateKey(outbio,mydsa,enc,NULL,0,NULL, NULL);
      PEM_write_bio_DSA_PUBKEY(outbio,mydsa);

      BIO_free(outbio);
   }

  return ret;
}
