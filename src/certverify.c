/* -------------------------------------------------------------------------- *
 * file:	certverify.cgi                                                *
 * purpose:	verify the certificate entries before signing the CSR         *
 * compile:     gcc -I/usr/local/ssl/include -L/usr/local/ssl/lib             *
 * certverify.c -o certverify.cgi -lcgic -lssl -lcrypto                       *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cgic.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "webcert.h"

/* add hardcoded definitions for the s/mime extension */
#define SMIME_OP        0x10
#define SMIME_IP        0x20
#define SMIME_SIGNERS   0x40
#define SMIME_ENCRYPT   (1 | SMIME_OP)
#define SMIME_DECRYPT   (2 | SMIME_IP)
#define SMIME_SIGN      (3 | SMIME_OP | SMIME_SIGNERS)
#define SMIME_VERIFY    (4 | SMIME_IP)
#define SMIME_PK7OUT    (5 | SMIME_IP | SMIME_OP)
#define SMIME_RESIGN    (6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS)

/* 
[ smime_seq ]
SMIMECapability.0 = SEQWRAP,OID:sha1
SMIMECapability.1 = SEQWRAP,OID:sha256
SMIMECapability.2 = SEQWRAP,OID:sha1WithRSA
SMIMECapability.3 = SEQWRAP,OID:aes-256-ecb
SMIMECapability.4 = SEQWRAP,OID:aes-256-cbc
SMIMECapability.5 = SEQWRAP,OID:aes-256-ofb
SMIMECapability.6 = SEQWRAP,OID:aes-128-ecb
SMIMECapability.7 = SEQWRAP,OID:aes-128-cbc
SMIMECapability.8 = SEQWRAP,OID:aes-128-ecb
SMIMECapability.9 = SEQUENCE:rsa_enc
*/

int cgiMain() {
   BIO 			    *inbio   = NULL;
   BIO                      *outbio  = NULL;
   X509_REQ 		*webrequest  = NULL;
   EVP_PKEY                   *pkey  = NULL;
   X509_NAME 		   *reqname  = NULL;
   char 		formreq[REQLEN] = "";
   static char 		title[] = "Verify Request";
   int                  filesize = 0;
   cgiFilePtr		file;

  /* ------------------------------------------------------------------------- *
   * Check form data if we got CSR data, or a CSR file, or nothing at all      *
   * --------------------------------------------------------------------------*/
   if (! (cgiFormString("csr-data", formreq, REQLEN) == cgiFormSuccess )) {
     if (! (cgiFormFileSize("csr-file", &filesize) == cgiFormSuccess)) {
         /* if we did not get a file either, we report failure */
         int_error("Error getting request from certrequest.cgi form");
      }
      /* we got a file, check the size is between 0 and REQLEN */
      if (filesize <=0 || filesize > REQLEN)
         int_error("Error uploaded request file size is to big");
     
      /* Try to open the file and get a file handle */
      if (cgiFormFileOpen("csr-file", &file) != cgiFormSuccess)
         int_error("Error unable to open the CSR file");

      /* we read the file content into our formreq buffer */
      if (! (cgiFormFileRead(file, formreq, REQLEN, &filesize) == cgiFormSuccess))
         int_error("Error uploaded request file is not readable");
   }

/* ------------------------------------------------------------------------- *
 * check if a CSR was pasted or if someone just sends garbage                *
 * --------------------------------------------------------------------------*/
   csr_validate(formreq);

/* ------------------------------------------------------------------------- *
 * input seems OK, write the request to a temporary mem BIO                  *
 * ------------------------------------------------------------------------- */
   inbio = BIO_new_mem_buf(formreq, -1);

/* ------------------------------------------------------------------------- *
 * Try to read the PEM request with openssl lib functions                    *
 * ------------------------------------------------------------------------- */

   if(! (webrequest = PEM_read_bio_X509_REQ(inbio, NULL, NULL, NULL)))
      int_error("Error cant read request content with PEM function");

   if(! (reqname = X509_REQ_get_subject_name(webrequest)))
      int_error("Error getting subject from cert request");

   if ((pkey=EVP_PKEY_new()) == NULL)
      int_error("Error creating EVP_PKEY structure.");

   if (! (pkey = X509_REQ_get_pubkey(webrequest)))
      int_error("Error getting public key from X509_REQ structure.");

/* ------------------------------------------------------------------------- *
 *  Sort out the content and start the html output                           *
 * ------------------------------------------------------------------------- */
   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   display_csr(webrequest);
   fprintf(cgiOut, "<p></p>\n");

   display_signing(webrequest);

   pagefoot();
   BIO_free(inbio);
   BIO_free(outbio);
   return(0);
}
