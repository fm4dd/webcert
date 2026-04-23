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
   /* ---------------------------------------------------------- *
    * Check form if we got CSR data, CSR file, or nothing at all *
    * -----------------------------------------------------------*/
   X509_REQ *webrequest  = NULL;
   char form[REQLEN] = "";
   if (cgiFormString("csrdata", form, REQLEN) == cgiFormSuccess)
      webrequest = cgi_load_csrform(form);
   else {
   /* ---------------------------------------------------------- *
    * Check if we got a csr file, load it into the CSR struct    * 
    * ---------------------------------------------------------- */
       char file_name[1024] = "";
       int ret = cgiFormFileName("csrfile", file_name, sizeof(file_name));

       if (ret == cgiFormSuccess)
          webrequest = cgi_load_csrfile(file_name);
       else
          /* If we did not get a file either, report failure */
          int_error("Error getting request from certrequest.cgi form");
   }
   /* ---------------------------------------------------------- *
    * Extract the name and public key from the CSR               *
    * ---------------------------------------------------------- */
   X509_NAME *reqname  = NULL;
   if(! (reqname = X509_REQ_get_subject_name(webrequest)))
      int_error("Error getting subject from cert request");

   EVP_PKEY *pkey  = NULL;
   if ((pkey=EVP_PKEY_new()) == NULL)
      int_error("Error creating EVP_PKEY structure.");

   if (! (pkey = X509_REQ_get_pubkey(webrequest)))
      int_error("Error getting public key from X509_REQ structure.");

   /* ---------------------------------------------------------- *
    *  Sort out the content and start the html output            *
    * ---------------------------------------------------------- */
    BIO *outbio = BIO_new(BIO_s_file());
    BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

    static char title[] = "Verify Request";
    pagehead(title);

    display_csr(webrequest);
    fprintf(cgiOut, "<p></p>\n");

    display_signing(webrequest);

    pagefoot();
    BIO_free(outbio);
    return(0);
}
