/* test_genreq.c			25/06/2005 frank4dd	     */
/* test example for generating a certificate with a                  */
/* rsa public/private key pair                                       */

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define KEYSIZE	1024

int main() {

  int ret=1;
  RSA *myrsa	=NULL;
  BIO *outbio	=NULL;
  const EVP_CIPHER *enc=NULL;

  X509_REQ     *webrequest      = NULL;
  X509_NAME    *reqname		= NULL;
  EVP_PKEY     *pubkey          = NULL;

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work. It is not well documented, I found out after looking into  *
 * the openssl source directly.                                               *
 * needed by: PEM_read_PrivateKey(), X509_REQ_verify() ...                    *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

   /* generate the rsa key */
   myrsa = RSA_new();
   myrsa = RSA_generate_key(KEYSIZE, RSA_F4, NULL, NULL);

   /* display the rsa key */
   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, stdout, BIO_NOCLOSE);
   PEM_write_bio_RSAPrivateKey(outbio,myrsa,enc,NULL,0,NULL, NULL);
   PEM_write_bio_RSA_PUBKEY(outbio,myrsa);

   /* assign key to EVP_KEY */
   if ((pubkey=EVP_PKEY_new()) == NULL)
      printf("Error creating EVP_PKEY structure.");

   if (!EVP_PKEY_assign_RSA(pubkey,myrsa))
      printf("Error assigning RSA key to EVP_PKEY structure.");
   
   /* generate the certificate */
   if ((webrequest=X509_REQ_new()) == NULL)
      printf("Error creating X509_REQ structure.");

   X509_REQ_set_pubkey(webrequest, pubkey);

   reqname=X509_REQ_get_subject_name(webrequest);

   /* This function creates and adds the entry, working out the
    * correct string type and performing checks on its length.
    * Normally we'd check the return value for errors...
    */
    X509_NAME_add_entry_by_txt(reqname,"C",
                                MBSTRING_ASC, "UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(reqname,"CN",
                                MBSTRING_ASC, "OpenSSL Group", -1, -1, 0);

    if (!X509_REQ_sign(webrequest,pubkey,EVP_md5()))
       printf("Error signing X509_REQ structure.");

    if (! PEM_write_bio_X509_REQ(outbio, webrequest))
       printf("Error printing the request");

   BIO_free(outbio);
   return ret;
}
