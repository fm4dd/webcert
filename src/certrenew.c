/* -------------------------------------------------------------------------- *
 * file:	certrenew.cgi                                                 *
 * purpose:     Generate a CSR from existig cert data (Need private key data) *
 * compile:     gcc -I/usr/local/ssl/include -L/usr/local/ssl/lib             *
 * certrenew.c -o certrenew.cgi -lcgic -lssl -lcrypto                         *
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

/* ---------------------------------------------------------- *
 * This function adds missing OID's to the internal structure *
 * ---------------------------------------------------------- */
void add_missing_smime_oids();

/* ---------------------------------------------------------- *
 * csr_validate() does a basic check for the CSR's PEM format *
 * ---------------------------------------------------------- */
void csr_validate(char *);

int cgiMain() {

   BIO 			    *inbio   = NULL;
   BIO                      *outbio  = NULL;
   X509 		      *cert  = NULL;
   EVP_PKEY                   *pkey  = NULL;
   X509_NAME 		   *reqname  = NULL;
   X509_NAME_ENTRY 	*e;
   STACK_OF(X509_EXTENSION)
                       *ext_list = NULL;
   int 			i;
   char 		buf[80] = "";
   char 		formreq[REQLEN] = "";
   static char 		title[] = "Certificate Renewal";

   int                  filesize = 0;
   cgiFilePtr		file;
   time_t       now              = 0;
   struct tm    *tm;
   char         startdate[11]    ="";
   char         enddate[11]      ="";
   char         starttime[9]     ="";
   char         endtime[9]       ="";

/* ------------------------------------------------------------------------- *
 * check if a certificate request was handed to certverify.cgi               *
 * or if someone just tried to call us directly without a request            *
 * --------------------------------------------------------------------------*/

   /* Check if we got certificate data to convert into a CSR */
   if (! (cgiFormString("cert-renew", formreq, REQLEN) == cgiFormSuccess )) {
         int_error("Error no certificate data received from certstore.cgi");
   }

/* ------------------------------------------------------------------------- *
 * check if a CSR was pasted or if someone just sends garbage                *
 * --------------------------------------------------------------------------*/
   // cert_validate(formreq);

/* ------------------------------------------------------------------------- *
 * input seems OK, write the request to a temporary mem BIO                  *
 * ------------------------------------------------------------------------- */
   inbio = BIO_new_mem_buf(formreq, -1);

/* ------------------------------------------------------------------------- *
 * Try to read the PEM request with openssl lib functions                    *
 * ------------------------------------------------------------------------- */

   if(! (cert = PEM_read_bio_X509(inbio, NULL, NULL, NULL)))
      int_error("Error cant read request content with PEM function");

/* ------------------------------------------------------------------------- *
 *  Sort out the content and start the html output                           *
 * ------------------------------------------------------------------------- */
   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   fprintf(cgiOut, "<h3>Under Construction!</h3>");
   fprintf(cgiOut, "<hr />");
   fprintf(cgiOut, "<p>Generating a CSR from a existing cert file for easy cert renewal.</p>");
   fprintf(cgiOut, "<table>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "PEM cert data of this certificate request:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<td><pre>\n");
    PEM_write_bio_X509(outbio, cert);
    fprintf(cgiOut, "</pre></td>\n");
   fprintf(cgiOut, "</tr>");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "<p></p>\n");

   pagefoot();
   BIO_free(inbio);
   BIO_free(outbio);
   return(0);
}

/* ---------------------------------------------------------- *
 * OpenSSL seems to lack a few OID's used for EV certificates *
 * ---------------------------------------------------------- */
void add_missing_smime_oids() {
/* get the nid integer for the S/MIME Capapbilities */
/* 1.2.840.113549.1.9.15 */
int smime_nid = OBJ_ln2nid("S/MIME Capabilities");
/* convert the NID into a ASN1 Object */
ASN1_OBJECT* smime_obj = OBJ_nid2obj(smime_nid);

    /* Create data to be included in the extension */
    ASN1_OCTET_STRING* data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(data, (const unsigned char *) "our data", -1);

    /**
     * This will create our new extension, identified by our OID (obj
     * parameter). And with the data created above (data
     * parameter). The 0 means that the extension is non-critical.
     */
    X509_EXTENSION_create_by_OBJ(NULL, smime_obj, 0, data);

  /* --------------------------------------------------------- *
   * OBJ_create():                                             *
   * First field is the OID, which will be converted to DER    *
   * encoding. Next are the long and short description of      *
   * this OID. The descriptions will not be included as the    *
   * extension identifier, but the DER encoding of the OID.    *
   * --------------------------------------------------------- */
  OBJ_create("1.3.6.1.4.1.311.60.2.1.1",
             "jurisdiction Of Incorporation LocalityName",
             "jurisdiction Of Incorporation LocalityName");

  OBJ_create("1.3.6.1.4.1.311.60.2.1.2",
             "jurisdiction Of Incorporation StateOrProvinceName",
             "jurisdiction Of Incorporation StateOrProvinceName");

  OBJ_create("1.3.6.1.4.1.311.60.2.1.3",
             "jurisdiction Of Incorporation CountryName",
             "jurisdiction Of Incorporation CountryName");

  /* Logo Type definition, see http://www.ietf.org/rfc/rfc3709 */
  OBJ_create("1.3.6.1.5.5.7.1.12",
             "id-pe-logotype",
             "id-pe-logotype");
}
