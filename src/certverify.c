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
   X509_REQ 		*webrequest  = NULL;
   EVP_PKEY                   *pkey  = NULL;
   X509_NAME 		   *reqname  = NULL;
   X509_NAME_ENTRY 	*e;
   STACK_OF(X509_EXTENSION)
                       *ext_list = NULL;
   int 			i;
   char 		buf[80] = "";
   char 		formreq[REQLEN] = "";
   static char 		title[] = "Verify Request";

   int                  filesize = 0;
   cgiFilePtr		file;
   time_t       now              = 0;
   struct tm    *tm;
   char         startdate[11]    ="";
   char         enddate[11]      ="";
   char         starttime[9]     ="";
   char         endtime[9]       ="";

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

/* ------------------------------------------------------------------------ *
 * Calculate default date and time strings                                  *
 * ------------------------------------------------------------------------ */
   now = time(NULL);
   tm = gmtime(&now);

   if (tm == NULL) {
     strncpy(startdate, "YYYY-MM-DD", sizeof(startdate));
     strncpy(starttime, "HH:MM:SS", sizeof(starttime));
   }
   else {
     strftime(startdate, sizeof(startdate), "%Y-%m-%d", tm);
     strftime(starttime, sizeof(starttime), "%H:%M:%S", tm);
   }

   now = now + (time_t) (DAYS_VALID*60*60*24);
   tm = gmtime(&now);

   if (tm == NULL) {
     strncpy(enddate, "YYYY-MM-DD", sizeof(enddate));
     strncpy(endtime, "HH:MM:SS", sizeof(endtime));
   }
   else {
     strftime(enddate, sizeof(enddate), "%Y-%m-%d", tm);
     strftime(endtime, sizeof(endtime), "%H:%M:%S", tm);
   }

/* ------------------------------------------------------------------------- *
 *  Sort out the content and start the html output                           *
 * ------------------------------------------------------------------------- */
   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   fprintf(cgiOut, "<form action=\"certsign.cgi\" method=\"post\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"sign-request\" ");
   fprintf(cgiOut, "value=\"%s\">\n", formreq);
   fprintf(cgiOut, "<table>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Subject data of this certificate request:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");

   for (i = 0; i < X509_NAME_entry_count(reqname); i++) {
      e = X509_NAME_get_entry(reqname, i);
      OBJ_obj2txt(buf, 80, e->object, 0);

      fprintf(cgiOut, "<tr>");
      fprintf(cgiOut, "<td class=type180>");
      fprintf(cgiOut, "%s</td>", buf);
      fprintf(cgiOut, "<td>");
      ASN1_STRING_print_ex(outbio, e->value, ASN1_STRFLGS_UTF8_CONVERT);
      fprintf(cgiOut, "</td>");
      fprintf(cgiOut, "</tr>\n");
   }

   /* If our certificate request includes extensions, we display here */
   if ((ext_list = X509_REQ_get_extensions(webrequest)) != NULL) {
     fprintf(cgiOut, "<tr>");
     fprintf(cgiOut, "<th colspan=\"2\">");
     fprintf(cgiOut, "Extensions within this certificate request: %d", sk_X509_EXTENSION_num(ext_list));
     fprintf(cgiOut, "</th>");
     fprintf(cgiOut, "</tr>\n");

     /* display the cert extension list here */
     for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ext;

        ext = sk_X509_EXTENSION_value(ext_list, i);
        obj = X509_EXTENSION_get_object(ext);

        fprintf(cgiOut, "<tr>");
        fprintf(cgiOut, "<td class=type180>");
        i2a_ASN1_OBJECT(outbio, obj);
        fprintf(cgiOut, "</td>");

        fprintf(cgiOut, "<td>");
        if (!X509V3_EXT_print(outbio, ext, 0, 0)) {
        /* Some extensions (i.e. LogoType) have no handling    *
         * defined, we need to print their content as hex data */
          fprintf(cgiOut, "%*s", 0, "");
          M_ASN1_OCTET_STRING_print(outbio, ext->value);
        }
        fprintf(cgiOut, "</td>");
        fprintf(cgiOut, "</tr>\n");
     }
   }

  /* display the key type and size here */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">Public key data for this certificate request:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "<td colspan=\"2\" class=\"getcert\">");
  if (pkey) {
    EC_KEY *myecc = NULL;
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(cgiOut, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(cgiOut, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_EC:
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        fprintf(cgiOut, "%d bit ECC Key, type %s", EVP_PKEY_bits(pkey),
                            OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
        break;
      default:
        fprintf(cgiOut, "%d bit %s Key", EVP_PKEY_bits(pkey), OBJ_nid2sn(pkey->type));
        break;
    }
  }
 
   fprintf(cgiOut, " <a href=\"javascript:elementHideShow('pubkey');\">\n");
   fprintf(cgiOut, "Expand or Hide Public Key Data</a>");
   /* display the public key data in PEM format here */
   fprintf(cgiOut, "<pre><div class=\"showpem\" id=\"pubkey\" style=\"display: none\">");
   if(!PEM_write_bio_PUBKEY(outbio, pkey))
     BIO_printf(outbio, "Error writing public key data in PEM format");
   fprintf(cgiOut, "</div></pre>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

  ASN1_STRING     *asn1_sig = NULL;
  X509_ALGOR      *sig_type = NULL;
  size_t          sig_bytes = 0;
  char   sig_type_str[1024] = "";

  /* ---------------------------------------------------------- *
   * Extract the certificate's signature data.                  *
   * ---------------------------------------------------------- */
  sig_type = webrequest->sig_alg;
  asn1_sig = webrequest->signature;
  sig_bytes = asn1_sig->length;
  OBJ_obj2txt(sig_type_str, sizeof(sig_type_str), sig_type->algorithm, 0);

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">Signature:</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<td  colspan=\"2\" class=\"getcert\">");

  fprintf(cgiOut, "%s, Length: %d Bytes\n", sig_type_str, (int) sig_bytes);
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqsig');\">\n");
  fprintf(cgiOut, "Expand or Hide Signature Data</a>");
  /* display the signature in hex byte format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"reqsig\"  style=\"display: none\"><pre>");
  if (X509_signature_dump(outbio, asn1_sig, 0) != 1)
    BIO_printf(outbio, "Error printing the signature data\n");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "<p></p>\n");

   /* Add Certificate extensions, Define validity */
   fprintf(cgiOut, "<table>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"3\">");
   fprintf(cgiOut, "Define certificate details:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   /* Add Key Usage */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"checkbox\" name=\"keyusage\" checked id=\"key_cb\" onclick=\"switchGrey('key_cb', 'key_td', 'none', 'none');\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Key Usage:</td>");
   fprintf(cgiOut, "<td id=\"key_td\" style=\"padding: 0;\">");
   fprintf(cgiOut, "<table style=\"border-style: none;\"><tr><td>");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=sv checked>");
   fprintf(cgiOut, " SSL Server</td></tr><tr>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=cl>");
   fprintf(cgiOut, " SSL Client</td></tr><tr>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=em>");
   fprintf(cgiOut, " E-Mail Encryption ");
   fprintf(cgiOut, "<input type=text size=20 name=\"ename\">");
   fprintf(cgiOut, " Address</td></tr><tr>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=os>");
   fprintf(cgiOut, " Object Signing</td></tr><tr>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=ca>");
   fprintf(cgiOut, " CA Certificate</td></tr>");
   fprintf(cgiOut, "</td></tr></table></td></tr>\n");

   /* Add extended key usage */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"checkbox\" name=\"extkeyusage\" id=\"exkey_cb\" onclick=\"switchGrey('exkey_cb', 'exkey_td', 'none', 'none');\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Extended Key Usage:");
   fprintf(cgiOut, "</td>\n");

   fprintf(cgiOut, "<td id=\"exkey_td\" style=\"background-color: #CFCFCF;\">\n");
   fprintf(cgiOut, "<select name=\"extkeytype\">");
   fprintf(cgiOut, "<option value=\"tlsws\" selected=\"selected\">");
   fprintf(cgiOut, "TLS Web server authentication</option>");
   fprintf(cgiOut, "<option value=\"tlscl\">TLS Web client authentication</option>");
   fprintf(cgiOut, "<option value=\"cs\">Code Signing</option>");
   fprintf(cgiOut, "<option value=\"ep\">Email Protection</option>");
   fprintf(cgiOut, "<option value=\"ts\">Time Stamping</option>");
   fprintf(cgiOut, "<option value=\"ocsp\">OCSP Signing</option>");
   fprintf(cgiOut, "</select>");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   /* Set validity from now */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"days_cb\" value=vd checked onclick=\"switchGrey('days_cb', 'days_td', 'date_td', 'none');\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Set Validity (in Days):");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td id=\"days_td\">");
   fprintf(cgiOut, " From now until <input type=text name=\"daysvalid\" size=4 value=%d> Days", DAYS_VALID);
   fprintf(cgiOut, "<br />");
   fprintf(cgiOut, "365 = 1 year, 730 = 2 years, 1095 = 3 years, 1460 = 4 years, 1825 = 5 years");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   /* Set validity by date */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"date_cb\" value=se onclick=\"switchGrey('date_cb', 'date_td', 'days_td', 'none')\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Set Validity (by Date):");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td id=\"date_td\" style=\"background-color: #CFCFCF;\">");
   fprintf(cgiOut, "<input type=text name=\"startdate\" size=15 value=%s>", startdate);
   fprintf(cgiOut, " Start Date ");
   fprintf(cgiOut, "<input type=text name=\"starttime\" size=10 value=%s>", starttime);
   fprintf(cgiOut, " Start Time (UTC)");
   fprintf(cgiOut, "<br />");
   fprintf(cgiOut, "<input type=text name=\"enddate\" size=15 value=%s>", enddate);
   fprintf(cgiOut, " End Date &nbsp;");
   fprintf(cgiOut, "<input type=text name=\"endtime\" size=10 value=%s>", endtime);
   fprintf(cgiOut, " End Time (UTC)");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr><th colspan=\"3\">");
   fprintf(cgiOut, "<input type=\"button\" name=\"Forget it!\" value=");
   fprintf(cgiOut, "\"  Go Back  \" onclick=");
   fprintf(cgiOut, "\"self.location.href='certrequest.cgi'\">&nbsp;");
   fprintf(cgiOut, "&nbsp;<input type=\"button\" value=\"Print Page\" ");
   fprintf(cgiOut, "onclick=\"print(); return false;\">&nbsp;");
   fprintf(cgiOut, "&nbsp;<input type=\"submit\" value=\"Sign Request\">");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "</form>\n");

   fprintf(cgiOut, "<p></p>");
   fprintf(cgiOut, "<table>\n");

   /* display the request content in PEM format here */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Show certificate request data in PEM format:");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td class=\"getcert\">");
   fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqpem');\">\n");
   fprintf(cgiOut, "Expand/Hide Request data in PEM format</a>");
   fprintf(cgiOut, "<div class=\"showpem\" id=\"reqpem\"  style=\"display: none\">");
   fprintf(cgiOut, "<pre>\n");
   PEM_write_bio_X509_REQ(outbio, webrequest);
   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "&nbsp;</th></tr>\n");
   fprintf(cgiOut, "</table>\n");
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
