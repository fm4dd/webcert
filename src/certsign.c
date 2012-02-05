/* -------------------------------------------------------------------------- *
 * file:	certsign.cgi                                                  *
 * purpose:	sign the certificate request                                  *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "webcert.h"

int cgiMain() {

   BIGNUM			*bserial;
   ASN1_INTEGER			*aserial = NULL;
   EVP_PKEY                     *ca_privkey, *req_pubkey;
   EVP_MD                       const *digest = NULL;
   X509                         *newcert, *cacert;
   X509_REQ                     *certreq;
   X509_NAME                    *name;
   X509V3_CTX                   ctx;
   FILE                         *fp;
   BIO                          *inbio, *outbio, *savbio;
   static char			title[]         = "Signed Certificate";
   char 			formreq[REQLEN] = "";
   char 			reqtest[REQLEN] = "";
   char				beginline[81]   = "";
   char				endline[81]     = "";
   char				certfile[81]    = "";
   char				email_head[255] = "email:";
   char				email_name[248] = "";
   char				certfilestr[255]= "";
   char				validdaystr[255]= "";
   char				*typelist[] = { "sv","cl","em","os","ca" };
   int				type_res = 0;
   char				extkeytype[81]  = "";
   long				valid_days = 0;
   long				valid_secs = 0;

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work. It is not well documented, I found out after looking into  *
 * the openssl source directly.                                               *
 * needed by: PEM_read_PrivateKey(), X509_REQ_verify() ...                    *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

/* -------------------------------------------------------------------------- *
 * check if a certificate was handed to certsign.cgi                          *
 * or if someone just tried to call us directly without a request             *
 * -------------------------------------------------------------------------- */

   if (! (cgiFormString("cert-request", formreq, REQLEN) == cgiFormSuccess ))
      int_error("Error getting request from certverify.cgi form");

   if (! (cgiFormString("edate", validdaystr, DAYS_VALID) == cgiFormSuccess ))
      int_error("Error getting expiration from certverify.cgi form");

/* -------------------------------------------------------------------------- *
 * What happens if a negative value is given as the expiration date?          *
 * The certificate is generated with a expiration before it becomes valid.    *
 * We do a check here to prevent that.                                        *
 * -------------------------------------------------------------------------- */

   valid_days = strtoul(validdaystr, NULL, 10);
   if (valid_days <= 0)
      int_error("Error negative or zero value for expiration date.");

/* -------------------------------------------------------------------------- *
 * What happens if a very large value is given as the expiration date?        *
 * The date rolls over to the old century (1900) and the expiration date      *
 * becomes invalid. We do a check here to prevent that.                       *
 * The max is 11663 days on Feb 12, 2006 and points to Jan 18th, 2038         *
 * The value is stored in type long, but somewhere lower the stuff fails      *
 * if valid_secs is bigger then 1007683200 (i.e. 1007769600). ca 32 years.    *
 * -------------------------------------------------------------------------- */
   if (valid_days > 11663)
      int_error("Error expiration date set to far in the future.");
   /* now we calculate the expiration in seconds: */
   valid_secs = valid_days*60*60*24;
 
   //for debug: store the value for X509_gmtime_adj in a string and display it:
   //sprintf(email_name, "%ld", valid_secs); int_error(email_name);

   if (cgiFormRadio("type", typelist, 5, &type_res, 0) == cgiFormNotFound )
      int_error("Error getting cert type(s) from previous form");

   if (cgiFormCheckboxSingle("extkeyusage") == cgiFormSuccess) {
       /* get the requested extended key usage type */
       if (cgiFormString("extkeytype", extkeytype, 81) == cgiFormNotFound ) {
           int_error("Error getting extended key usage type from previous form");
       }
    }

/* -------------------------------------------------------------------------- *
 * check if a certificate was pasted or if someone just typed                 *
 * a line of garbage                                                          *
 * -------------------------------------------------------------------------- */

   if (! strchr(formreq, '\n'))
      int_error("Error invalid request format, received garbage line");

/* -------------------------------------------------------------------------- *
 * check if a certificate was pasted with the BEGIN and END                   *
 * lines, assuming the request in between is intact                           *
 * -------------------------------------------------------------------------- */

   strcpy(reqtest, formreq);
   strcpy(endline, (strrchr(reqtest, '\n') +1));
   /* should there be a extra newline at the end, we remove it here */
   if(strlen(endline) == 0 && strlen(reqtest) > 0) {
      reqtest[strlen(reqtest)-1]='\0';
      strcpy(endline, (strrchr(reqtest, '\n') +1));
   }
   strtok(reqtest, "\n");
   strcpy(beginline, reqtest);

   if(! ( (strcmp(beginline, "-----BEGIN CERTIFICATE REQUEST-----") == 0 &&
         strcmp(endline, "-----END CERTIFICATE REQUEST-----") == 0)
         ||

        (strcmp(beginline, "-----BEGIN NEW CERTIFICATE REQUEST-----") == 0 &&
         strcmp(endline, "-----END NEW CERTIFICATE REQUEST-----") == 0) ) )
      int_error("Error invalid request format, no BEGIN/END lines");

/* -------------------------------------------------------------------------- *
 * input seems OK, write the request to a temporary BIO buffer                *
 * ---------------------------------------------------------------------------*/

  inbio = BIO_new_mem_buf(formreq, -1);

/* -------------------------------------------------------------------------- *
 * Try to read the PEM request with openssl lib functions                     *
 * ---------------------------------------------------------------------------*/

   if (! (certreq = PEM_read_bio_X509_REQ(inbio, NULL, NULL, NULL)))
      int_error("Error can't read request content with PEM function");

/* -------------------------------------------------------------------------- *
 * Certificate request public key verification                                * 
 * ---------------------------------------------------------------------------*/

   req_pubkey = EVP_PKEY_new();
   if ( (certreq->req_info == NULL) ||
        (certreq->req_info->pubkey == NULL) ||
        (certreq->req_info->pubkey->public_key == NULL) ||
        (certreq->req_info->pubkey->public_key->data == NULL))
        {
           int_error("Error missing public key in request");
        }
   if (! (req_pubkey=X509_REQ_get_pubkey(certreq)))
           int_error("Error unpacking public key from request");
   if (X509_REQ_verify(certreq,req_pubkey) != 1)
      int_error("Error verifying signature on request");

/* -------------------------------------------------------------------------- *
 * Load CA Certificate from file for signer info                              *
 * ---------------------------------------------------------------------------*/

   if (! (fp=fopen(CACERT, "r")))
      int_error("Error reading CA cert file");
   if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL)))
      int_error("Error loading CA cert into memory");
   fclose(fp);

/* -------------------------------------------------------------------------- *
 * Import CA private key for signing                                          *
 * ---------------------------------------------------------------------------*/

   ca_privkey = EVP_PKEY_new();
   if (! (fp = fopen (CAKEY, "r")))
      int_error("Error reading CA private key file");
   if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS)))
      int_error("Error importing key content from file");
   fclose(fp);

/* -------------------------------------------------------------------------- *
 * Build Certificate with data from request                                   *
 * ---------------------------------------------------------------------------*/

   if (! (newcert=X509_new()))
      int_error("Error creating new X509 object");

   if (X509_set_version(newcert, 2L) != 1)
      int_error("Error setting certificate version");

/* -------------------------------------------------------------------------- *
 * load the serial number from SERIALFILE                                     *
 * ---------------------------------------------------------------------------*/

   if (! (bserial = load_serial(SERIALFILE, 1, NULL)))
      int_error("Error getting serial # from serial file");

/* -------------------------------------------------------------------------- *
 * increment the serial number                                                *
 * ---------------------------------------------------------------------------*/

   if (! (BN_add_word(bserial,1)))
      int_error("Error incrementing serial number"); 

/* -------------------------------------------------------------------------- *
 * save the serial number back to SERIALFILE                                  *
 * ---------------------------------------------------------------------------*/

   if ( save_serial(SERIALFILE, 0, bserial, &aserial) == 0 )
      int_error("Error writing serial number to file");

/* -------------------------------------------------------------------------- *
 * set the certificate serial number here                                     *
 * ---------------------------------------------------------------------------*/

   if (! X509_set_serialNumber(newcert, aserial))
      int_error("Error setting serial number of the certificate");

   if (! (name = X509_REQ_get_subject_name(certreq)))
      int_error("Error getting subject from cert request");
   if (X509_set_subject_name(newcert, name) != 1)
   if (! (name = X509_REQ_get_subject_name(certreq)))
      int_error("Error getting subject from cert request");
   if (X509_set_subject_name(newcert, name) != 1)
      int_error("Error setting subject name of certificate");
   if (! (name = X509_get_subject_name(cacert)))
      int_error("Error getting subject from CA certificate");
   if (X509_set_issuer_name(newcert, name) != 1)
      int_error("Error setting issuer name of certificate");

   if (X509_set_pubkey(newcert, req_pubkey) != 1)
      int_error("Error setting public key of certificate");
   EVP_PKEY_free(req_pubkey);

/* -------------------------------------------------------------------------- *
 * Set X509V3 start date and expiration date here                             *
 * ---------------------------------------------------------------------------*/

   if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0)))
      int_error("Error setting beginning time of certificate");

   if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs)))
      int_error("Error setting expiration time of certificate");

/* -------------------------------------------------------------------------- *
 * Add X509V3 extensions                                                      *
 * ---------------------------------------------------------------------------*/

   X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);
   X509_EXTENSION *ext;

   /* Unless we sign a CA cert, always add the CA:FALSE constraint */
   if (strcmp(typelist[type_res], "ca") != 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                                  "basicConstraints", "critical,CA:FALSE"))) {
         int_error("Error creating X509 extension object");
      }
   if (! X509_add_ext(newcert, ext, -1))
      int_error("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);
   } else {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                                  "basicConstraints", "critical,CA:TRUE"))) {
         int_error("Error creating X509 extension object");
      }
   if (! X509_add_ext(newcert, ext, -1))
      int_error("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);
   }

   /* If we sign a server cert, add the nsComment extension */
   if (strcmp(typelist[type_res], "sv") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "nsComment", "SSL enabling server cert")))
         int_error("Error creating X509 extension object");
   if (! X509_add_ext(newcert, ext, -1))
      int_error("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "sv") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature,keyEncipherment"))) {
         int_error("Error creating X509 keyUsage extension object");
      }

     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "cl") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature"))) {
         int_error("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "em") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature,keyEncipherment"))) {
         int_error("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "os") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "digitalSignature"))) {
         int_error("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (strcmp(typelist[type_res], "ca") == 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "keyUsage", "keyCertSign,cRLSign"))) {
         int_error("Error creating X509 keyUsage extension object");
      }
     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

   if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "subjectKeyIdentifier", "hash"))) {
       int_error("Error creating X509 subjectKeyIdentifier extension object");
   }
   if (! X509_add_ext(newcert, ext, -1))
      int_error("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);

   if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "authorityKeyIdentifier", "keyid, issuer:always"))) {
      int_error("Error creating X509 authorityKeyIdentifier extension object");
   }
   if (! X509_add_ext(newcert, ext, -1))
      int_error("Error adding X509 extension to certificate");
   X509_EXTENSION_free(ext);

   if (strcmp(typelist[type_res], "em") == 0) {
     if(cgiFormString("ename", email_name, sizeof(email_name)) == cgiFormSuccess) {
       strncat(email_head, email_name, sizeof(email_head) - strlen(email_head));
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                     "subjectAltName", email_head)))
         int_error("Error creating X509 e-mail extension object");

       if (! X509_add_ext(newcert, ext, -1))
          int_error("Error adding X509 extension to certificate");
       X509_EXTENSION_free(ext);
     } else
      int_error("Error - No e-mail address given.");
   }

  
   /* if extended key usgaes has been requested,we add it here */
   /* http://tools.ietf.org/html/rfc5280#section-4.2.1.12      */
   /* http://www.openssl.org/docs/apps/x509v3_config.html      */
   if (cgiFormCheckboxSingle("extkeyusage") == cgiFormSuccess) {
 
     if (strcmp(extkeytype, "tlsws") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "serverAuth"))) {
          int_error("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "tlscl") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "clientAuth"))) {
          int_error("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "cs") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "codeSigning"))) {
          int_error("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ep") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "emailProtection"))) {
          int_error("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ts") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "timeStamping"))) {
          int_error("Error creating X509 keyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ocsp") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "OCSPSigning"))) {
          int_error("Error creating X509 keyUsage extension object");
       }
     }
     if (! X509_add_ext(newcert, ext, -1))
         int_error("Error adding X509 extension to certificate");
     X509_EXTENSION_free(ext);
   }

/* -------------------------------------------------------------------------- *
 * Sign the new certificate with CA private key                               *
 * ---------------------------------------------------------------------------*/

   if (EVP_PKEY_type(ca_privkey->type) == EVP_PKEY_DSA)
      digest = EVP_dss1();
   else if (EVP_PKEY_type(ca_privkey->type) == EVP_PKEY_RSA)
      digest = EVP_sha1();
   else
      int_error("Error checking CA private key for valid digest");
   if (! X509_sign(newcert, ca_privkey, digest))
      int_error("Error signing the new certificate");

/* -------------------------------------------------------------------------- *
 *  print the certificate                                                     *
 * ---------------------------------------------------------------------------*/

   snprintf(certfile, sizeof(certfile), "%s.pem", BN_bn2hex(bserial));

   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   fprintf(cgiOut, "<table border=\"1\" cellspacing=\"0\" ");
   fprintf(cgiOut, "cellpadding=\"2\" width=\"100%%\">");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "Your new certificate %s is displayed below:", certfile);
   fprintf(cgiOut, "</th></tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"getcert\">\n");
   fprintf(cgiOut, "<pre>\n");
   fprintf(cgiOut, "<div id=\"getpem\">\n");

   if (! PEM_write_bio_X509(outbio, newcert))
      int_error("Error printing the signed certificate");

   fprintf(cgiOut, "</div></pre></td></tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "<p><center>");
   fprintf(cgiOut, "<table border=\"1\" cellspacing=\"0\" ");
   fprintf(cgiOut, "cellpadding=\"0\" width=\"100%%\">");
   fprintf(cgiOut, "<tr>\n");

   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Show PEM\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\">");
   fprintf(cgiOut, "</th></form>\n");

   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Show Text\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"text\">");
   fprintf(cgiOut, "</th></form>\n");

   // filler 1 separating view from export
   fprintf(cgiOut, "<th width=100>");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Export P12\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"p12\">");
   fprintf(cgiOut, "</th></form>\n");

   fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Export PEM\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\">");
   fprintf(cgiOut, "</th></form>\n");

   fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Export DER\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"der\">");
   fprintf(cgiOut, "</th></form>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   BIO_free(outbio);
/* -------------------------------------------------------------------------- *
 *  write a certificate backup to local disk, named after its serial number   *
 * ---------------------------------------------------------------------------*/

   snprintf(certfilestr, sizeof(certfilestr), "%s/%s.pem", CACERTSTORE,
                                                          BN_bn2hex(bserial));
   if (! (fp=fopen(certfilestr, "w")))
     fprintf(cgiOut, "<p>Error open cert file %s for writing.<p>", certfilestr);
   else {
     savbio = BIO_new(BIO_s_file());
     BIO_set_fp(savbio, fp, BIO_NOCLOSE);
     if (! PEM_write_bio_X509(savbio, newcert))
        fprintf(cgiOut, "Error writing the signed cert file %s.<p>",
                                                                   certfilestr);
   BIO_free(savbio);
   fclose(fp);
   }

   pagefoot();
   BIO_free(inbio);
   return(0);
}
