/* -------------------------------------------------------------------------- *
 * file:	certsign.cgi                                                  *
 * purpose:	sign the certificate request                                  *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "webcert.h"

char * mkdatestr(char *, char *);

int check_ext_presence(X509_EXTENSION *test_ext, X509 *cert);

int cgiMain() {
   BIGNUM       *bserial;
   ASN1_INTEGER	*aserial = NULL;
   EVP_PKEY     *ca_privkey, *req_pubkey;
   EVP_MD        const *digest = NULL;
   X509          *newcert, *cacert;
   X509_NAME     *name;
   X509V3_CTX    ctx;
   FILE          *fp;
   char	  certfile[81]    = "";
   char	  email_head[255] = "email:";
   char	  email_name[248] = "";
   char	 certfilestr[255] = "";
   char	     *validlist[] = { "vd","se" };
   int	        valid_res = 0;
   char  startdatestr[16] = "";
   char     startdate[11] = "";
   char      starttime[9] = "";
   char    enddatestr[16] = "";
   char       enddate[11] = "";
   char        endtime[9] = "";
   char	 validdaystr[255] = "";
   char	    sigalgstr[41] = "SHA-256";
   char	      *typelist[] = { "sv","cl","em","os","ca" };
   int	         type_res = 0;
   char	   extkeytype[81] = "";
   long	       valid_days = 0;
   long	       valid_secs = 0;
   time_t             now = 0;

/* ---------------------------------------------------------- *
 * These function calls are essential to make many PEM +      *
 * other openssl functions work.                              *
 * ---------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
   ERR_load_BIO_strings();

/* ---------------------------------------------------------- *
 * check if a certificate was handed to certsign.cgi or if    *
 * someone just tried to call us directly without a request   *
 * ---------------------------------------------------------- */
   X509_REQ *certreq = NULL;
   char formreq[REQLEN] = "";

   if (cgiFormString("csrdata", formreq, REQLEN) != cgiFormSuccess)
      int_error("Error getting CSR data from genrequest/certverify.cgi form");

   certreq = cgi_load_csrform(formreq);

   if (cgiFormRadio("valid", validlist, 2, &valid_res, 0) == cgiFormNotFound )
      int_error("Error getting the date range type from genrequest/certverify.cgi forms");

   if (strcmp(validlist[valid_res], "vd") == 0) {
      if(cgiFormString("daysvalid", validdaystr, DAYS_VALID) != cgiFormSuccess)
        int_error("Error getting expiration from genrequest/certverify.cgi form");

   if(cgiFormString("sigalg", sigalgstr, sizeof(sigalgstr)) != cgiFormSuccess)
      int_error("Error getting the signature algorithm from genrequest/certverify.cgi forms");

/* -------------------------------------------------------------------------- *
 * What happens if a negative value is given as the expiration date?          *
 * The certificate is generated with a expiration before it becomes valid.    *
 * We do a check here to prevent that.                                        *
 * -------------------------------------------------------------------------- */
   /* convert the number string to data type long, max is 10 digits */
   valid_days = strtoul(validdaystr, NULL, 10);
   if (valid_days <= 0)
      int_error("Error invalid (i.e. negative or zero) value for expiration date.");

   /* convert days into (long) seconds */
   valid_secs = valid_days*60*60*24;
   now = time(NULL);
/* -------------------------------------------------------------------------- *
 * year 2038 32bit Unix time integer overflow:                                *
 * What happens if a very large value is given as the expiration date?        *
 * The date rolls over to the old century (1900) and the expiration date      *
 * becomes invalid. We do a check here to prevent that.                       *
 * Although we store the value in type long, 32bit UNIX systems historically  *
 * used a 32bit integertype for counting seconds since Jan 1, 1970.           *
 * This will cause a range overflow when we reach the year 2038, and the sec  *
 * counter reaches 2,147,483,647, the max value for a unsigned 32bit integer. *
 * -------------------------------------------------------------------------- */
#ifdef TIME_PROTECTION
      long future = now + valid_secs;
      if (future > 2147483647 || future < 0)
         int_error("Error expiration date set past 2038, causing trouble on 32bit.");
#endif
   }

   if (strcmp(validlist[valid_res], "se") == 0) {
      if (! (cgiFormString("startdate", startdate, 11) == cgiFormSuccess ))
         int_error("Error getting start date from previous form");
      if (! (cgiFormString("starttime", starttime, 9) == cgiFormSuccess ))
         int_error("Error getting start time from previous form");
      if (! (cgiFormString("enddate", enddate, 11) == cgiFormSuccess ))
         int_error("Error getting end date from previous form");
      if (! (cgiFormString("endtime", endtime, 11) == cgiFormSuccess ))
         int_error("Error getting end time from previous form");

      strncpy(startdatestr, mkdatestr(startdate, starttime), 16);
      strncpy(enddatestr, mkdatestr(enddate, endtime), 16);
   }

   if (cgiFormRadio("type", typelist, 5, &type_res, 0) == cgiFormNotFound )
      int_error("Error getting cert type(s) from previous form");

   if (cgiFormCheckboxSingle("extkeyusage") == cgiFormSuccess) {
       /* get the requested extended key usage type */
       if (cgiFormString("extkeytype", extkeytype, 81) == cgiFormNotFound ) {
           int_error("Error getting extended key usage type from previous form");
       }
    }

/* ----------------------------------------------------------- *
 * Certificate request public key verification                 * 
 * ------------------------------------------------------------*/
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

/* ----------------------------------------------------------- *
 * Load CA Certificate from file for signer info               *
 * ------------------------------------------------------------*/
   if (! (fp=fopen(CACERT, "r")))
      int_error("Error reading CA cert file");
   if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL)))
      int_error("Error loading CA cert into memory");
   fclose(fp);

/* ----------------------------------------------------------- *
 * Import CA private key for signing                           *
 * ------------------------------------------------------------*/
   ca_privkey = EVP_PKEY_new();
   if (! (fp = fopen (CAKEY, "r")))
      int_error("Error reading CA private key file");
   if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS)))
      int_error("Error importing key content from file");
   fclose(fp);

/* ----------------------------------------------------------- *
 * Build Certificate with data from request                    *
 * ------------------------------------------------------------*/
   if (! (newcert=X509_new()))
      int_error("Error creating new X509 object");

   if (X509_set_version(newcert, 2L) != 1)
      int_error("Error setting certificate version");

/* ----------------------------------------------------------- *
 * load the serial number from SERIALFILE                      *
 * ------------------------------------------------------------*/
   if (! (bserial = load_serial(SERIALFILE, 1, NULL)))
      int_error("Error getting serial # from serial file");

/* ----------------------------------------------------------- *
 * increment the serial number                                 *
 * ------------------------------------------------------------*/
   if (! (BN_add_word(bserial,1)))
      int_error("Error incrementing serial number"); 

/* ----------------------------------------------------------- *
 * save the serial number back to SERIALFILE                   *
 * ------------------------------------------------------------*/
   if ( save_serial(SERIALFILE, 0, bserial, &aserial) == 0 )
      int_error("Error writing serial number to file");

/* ----------------------------------------------------------- *
 * set the certificate serial number here                      *
 * ------------------------------------------------------------*/
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

/* ----------------------------------------------------------- *
 * Set X509V3 start date "now", expire date "now+valid_secs"   *
 * ------------------------------------------------------------*/
   if (strcmp(validlist[valid_res], "vd") == 0) {
      if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0)))
         int_error("Error setting beginning time of certificate");

      if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs)))
         int_error("Error setting expiration time of certificate");
   }

/* ----------------------------------------------------------- *
 * Set X509V3 start and expire date if it was specifically set *
 * ------------------------------------------------------------*/
   if (strcmp(validlist[valid_res], "se") == 0) {
      if (! ASN1_TIME_set_string(X509_get_notBefore(newcert), startdatestr))
         int_error("Error start date is invalid, it should be YYYYMMDDHHMMSSZ");

      if (! ASN1_TIME_set_string(X509_get_notAfter(newcert), enddatestr))
         int_error("Error end date is invalid, it should be YYYYMMDDHHMMSSZ");
   }

/* ----------------------------------------------------------- *
 * Add X509V3 extensions                                       *
 * ------------------------------------------------------------*/
   STACK_OF(X509_EXTENSION) *ext_list = NULL;
   X509_EXTENSION *ext;
   int i;

   X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);

   /* if the certificte request contains extensions, we add them first */
   if ((ext_list = X509_REQ_get_extensions(certreq)) != NULL) {
     /* add each requested extension to the cert */
     for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
        ext = sk_X509_EXTENSION_value(ext_list, i);

        if (! X509_add_ext(newcert, ext, -1))
          int_error("Error adding X509 extension to certificate");

        X509_EXTENSION_free(ext);
     }
   }

   /* Unless we sign a CA cert, always add the CA:FALSE constraint */
   if (strcmp(typelist[type_res], "ca") != 0) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                                  "basicConstraints", "critical,CA:FALSE"))) {
         int_error("Error creating X509 extension object");
      }
      /* extension duplicates: check if the extension is already present */
      if (check_ext_presence(ext, newcert) == 0) {
        /* try to add it to the certificate */
        if (! X509_add_ext(newcert, ext, -1))
          int_error("Error adding X509 extension to certificate");
      }
      X509_EXTENSION_free(ext);
   /* a CA cert is requested, we add the CA:TRUE constraint */
   } else {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                                  "basicConstraints", "critical,CA:TRUE"))) {
         int_error("Error creating X509 basicConstraints extension object");
      }
      /* extension duplicates: check if the extension is already present */
      if (check_ext_presence(ext, newcert) == 0) {
         if (! X509_add_ext(newcert, ext, -1))
            int_error("Error adding X509 basicConstraints extension to certificate");
      }
      X509_EXTENSION_free(ext);
   }

   /* If enabled, add the following key usage extension */
   if (cgiFormCheckboxSingle("keyusage") == cgiFormSuccess) {
      if (strcmp(typelist[type_res], "sv") == 0) {
         if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                        "keyUsage", "digitalSignature,keyEncipherment"))) {
            int_error("Error creating X509 keyUsage extension object");
         }
   
         /* extension duplicates: check if the extension is already present */
         if (check_ext_presence(ext, newcert) == 0) {
            if (! X509_add_ext(newcert, ext, -1))
               int_error("Error adding X509 keyUsage extension to certificate");
         }
         X509_EXTENSION_free(ext);
      }
   
      if (strcmp(typelist[type_res], "cl") == 0) {
        if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                        "keyUsage", "digitalSignature"))) {
            int_error("Error creating X509 keyUsage extension object");
        }

        /* extension duplicates: check if the extension is already present */
        if (check_ext_presence(ext, newcert) == 0) {
          if (! X509_add_ext(newcert, ext, -1))
            int_error("Error adding X509 keyUsage extension to certificate");
        }
        X509_EXTENSION_free(ext);
      }
   
      if (strcmp(typelist[type_res], "em") == 0) {
        if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                        "keyUsage", "digitalSignature,keyEncipherment"))) {
           int_error("Error creating X509 keyUsage extension object");
        }
        /* extension duplicates: check if the extension is already present */
        if (check_ext_presence(ext, newcert) == 0) {
          if (! X509_add_ext(newcert, ext, -1))
            int_error("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free(ext);
      }
   
      if (strcmp(typelist[type_res], "os") == 0) {
        if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                        "keyUsage", "digitalSignature"))) {
           int_error("Error creating X509 keyUsage extension object");
        }
        /* extension duplicates: check if the extension is already present */
        if (check_ext_presence(ext, newcert) == 0) {
          if (! X509_add_ext(newcert, ext, -1))
           int_error("Error adding X509 keyUsage extension to certificate");
        }
        X509_EXTENSION_free(ext);
      }
   
      if (strcmp(typelist[type_res], "ca") == 0) {
        if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                       "keyUsage", "keyCertSign,cRLSign"))) {
           int_error("Error creating X509 keyUsage extension object");
        }
        /* extension duplicates: check if the extension is already present */
        if (check_ext_presence(ext, newcert) == 0) {
          if (! X509_add_ext(newcert, ext, -1))
             int_error("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free(ext);
      }
   
      if (strcmp(typelist[type_res], "em") == 0) {
        if(cgiFormString("ename", email_name, sizeof(email_name)) == cgiFormSuccess) {
          strncat(email_head, email_name, sizeof(email_head) - strlen(email_head));
          if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                        "subjectAltName", email_head)))
            int_error("Error creating X509 e-mail extension object");
   
          /* extension duplicates: check if the extension is already present */
          if (check_ext_presence(ext, newcert) == 0) {
            if (! X509_add_ext(newcert, ext, -1))
               int_error("Error adding X509 subjectAltName extension to certificate");
          }
          X509_EXTENSION_free(ext);
        } else
         int_error("Error - No e-mail address given.");
      }
   }

   /* Always add subjectKeyIdentifier */
   if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "subjectKeyIdentifier", "hash"))) {
       int_error("Error creating X509 subjectKeyIdentifier extension object");
   }

   /* extension duplicates: check if the extension is already present */
   if (check_ext_presence(ext, newcert) == 0) {
     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 subjectKeyIdentifier extension to certificate");
   }
   X509_EXTENSION_free(ext);

   /* Always add authorityKeyIdentifier */
   if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "authorityKeyIdentifier", "keyid, issuer:always"))) {
      int_error("Error creating X509 authorityKeyIdentifier extension object");
   }

   /* extension duplicates: check if the extension is already present */
   if (check_ext_presence(ext, newcert) == 0) {
     if (! X509_add_ext(newcert, ext, -1))
        int_error("Error adding X509 extension to certificate");
   }

   /* Add cRLDistributionPoints, URI see webcert.h */
   if (cgiFormCheckboxSingle("addcrluri") == cgiFormSuccess) {
      if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                  "crlDistributionPoints", CRLURI))) {
         int_error("Error creating X509 cRLDistributionPoints extension object");
      }

      /* extension duplicates: check if the extension is already present */
      if (check_ext_presence(ext, newcert) == 0) {
         if (! X509_add_ext(newcert, ext, -1))
            int_error("Error adding X509 extension to certificate");
      }
      X509_EXTENSION_free(ext);
   }

  
   /* ----------------------------------------------------------- *
    * If extended key usage has been requested,we add it here.    * 
    * http://tools.ietf.org/html/rfc5280#section-4.2.1.12         * 
    * http://www.openssl.org/docs/apps/x509v3_config.html         * 
    * ----------------------------------------------------------- */
   if (cgiFormCheckboxSingle("extkeyusage") == cgiFormSuccess) {
 
     if (strcmp(extkeytype, "tlsws") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "serverAuth"))) {
          int_error("Error creating X509 extendedKeyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "tlscl") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "clientAuth"))) {
          int_error("Error creating X509 extendedKeyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "cs") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "codeSigning"))) {
          int_error("Error creating X509 extendedKeyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ep") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "emailProtection"))) {
          int_error("Error creating X509 extendedKeyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ts") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "timeStamping"))) {
          int_error("Error creating X509 extendedKeyUsage extension object");
       }
     }
     if (strcmp(extkeytype, "ocsp") == 0) {
       if (! (ext = X509V3_EXT_conf(NULL, &ctx,
                      "extendedKeyUsage", "OCSPSigning"))) {
          int_error("Error creating X509 extendedKeyUsage extension object");
       }
     }
     /* extension duplicates: check if the extension is already present */
     if (check_ext_presence(ext, newcert) == 0) {
       if (! X509_add_ext(newcert, ext, -1))
           int_error("Error adding X509 extendedKeyUsage extension to certificate");
     }
     X509_EXTENSION_free(ext);
   }

/* ---------------------------------------------------------- *
 *  Set digest algorithm strength, use only SHA variants      *
 * ---------------------------------------------------------- */
   if(strcmp(sigalgstr, "SHA-224") == 0) digest = EVP_sha224();
   else if(strcmp(sigalgstr, "SHA-256") == 0) digest = EVP_sha256();
   else if(strcmp(sigalgstr, "SHA-384") == 0) digest = EVP_sha384();
   else if(strcmp(sigalgstr, "SHA-512") == 0) digest = EVP_sha512();
   else int_error("Error received unknown sigalg string");

/* ---------------------------------------------------------- *
 * Sign the new certificate with CA private key               *
 * ---------------------------------------------------------- */
   if (! X509_sign(newcert, ca_privkey, digest))
      int_error("Error signing the new certificate");

/* ---------------------------------------------------------- *
 *  print the certificate                                     *
 * ---------------------------------------------------------- */
   snprintf(certfile, sizeof(certfile), "%s.pem", BN_bn2hex(bserial));

   BIO *outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   static char title[]  = "Signed Certificate";
   pagehead(title);

   display_cert(newcert, "Server/System/Application", "wct_chain", -1);
   fprintf(cgiOut, "<p></p>\n");

   fprintf(cgiOut, "<table>");
   fprintf(cgiOut, "<tr>\n");

   // Print View
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<input type=\"button\" value=\"Print Page\" ");
   fprintf(cgiOut, "onclick=\"print(); return false;\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Export P12\" />\n");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\" />\n", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"p12\" />\n");
   fprintf(cgiOut, "</form>\n");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Export PEM\" />\n");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\" />\n", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\" />\n");
   fprintf(cgiOut, "</form>\n");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Export DER\" />\n");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\" />\n", certfile);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"der\" />\n");
   fprintf(cgiOut, "</form>\n");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   BIO_free(outbio);
/* ---------------------------------------------------------- *
 * write a certificate backup to local disk, named after its  *
 * serial number                                              *
 * -----------------------------------------------------------*/
   snprintf(certfilestr, sizeof(certfilestr), "%s/%s.pem", CACERTSTORE,
                                                          BN_bn2hex(bserial));
   if (! (fp=fopen(certfilestr, "w")))
     fprintf(cgiOut, "<p>Error open cert file %s for writing.<p>", certfilestr);
   else {
     BIO *savbio = BIO_new(BIO_s_file());
     BIO_set_fp(savbio, fp, BIO_NOCLOSE);
     if (! PEM_write_bio_X509(savbio, newcert))
        fprintf(cgiOut, "Error writing the signed cert file %s.<p>",
                                                                   certfilestr);
   BIO_free(savbio);
   fclose(fp);
   }

   pagefoot();
   return(0);
}

/* ---------------------------------------------------------- *
 * mkdatestr builds a string "YYYYMMDDHHMMSSZ" from the forms *
 * input strings date = YYYY-MM-DD (i.e. 2012-11-24), and     *
 * time = HH:MM:SS (i.e. 21:45:33)                            *
 * -----------------------------------------------------------*/
char * mkdatestr(char *date, char *time) {
  static char datestr[16] = "";
  char *err[16];
  char *tmp;
  long yr = 0; // year
  long mo = 0; // month
  long dy = 0; // day
  long hr = 0; // hour
  long mi = 0; // minutes
  long sc = 0; // seconds

  tmp = strtok(date, "-");
  if (strlen(tmp) != 0)
    yr = strtol(tmp, err, 10);

  if (strlen(*err) != 0)
    int_error("Error in date string: cannot extract year digits.");

#ifdef TIME_PROTECTION
  /* year 2038 bug workaround: we protect us from the integer overflow */
  if (yr < 1970 || yr > 2037)
    int_error("Error in date range: year is < 1970 or > 2037.");
#endif

  tmp = strtok(NULL, "-");
  if (strlen(tmp) != 0)
    mo = strtol(tmp, err, 10);

  if (strlen(*err) != 0)
    int_error("Error in date string: cannot extract month digits.");

  if (mo < 1 || mo > 12)
    int_error("Error in date range: month is < 1 or > 12.");

  tmp = strtok(NULL, "-");
  if (strlen(tmp) != 0)
    dy = strtol(tmp, err, 10);

  if (strlen(*err) != 0)
    int_error("Error in date string: cannot extract day digits.");

  if (dy < 1 || dy > 31)
    int_error("Error in date range: day is < 1 or > 31.");

  tmp = strtok(time, ":");
  if (strlen(tmp) != 0)
    hr = strtol(tmp, err, 10);

  if (strlen(*err) != 0)
    int_error("Error in time string: cannot extract the hour digits.");

  if (hr < 0 || hr > 23)
    int_error("Error in time range: hours are < 0 or > 23.");

  tmp = strtok(NULL, ":");
  if (strlen(tmp) != 0)
    mi = strtol(tmp, err, 10);

  if (strlen(*err) != 0)
    int_error("Error in time string: cannot extract the minute digits.");

  if (mi < 0 || mi > 59)
    int_error("Error in time range: minutes are < 0 or > 59.");

  tmp = strtok(NULL, ":");
  if (strlen(tmp) != 0)
   sc = strtol(tmp, err, 10);

  if (strlen(*err) != 0)
    int_error("Error in time string: cannot extract the second digits.");

  if (sc < 0 || sc > 59)
    int_error("Error in time range: seconds are < 0 or > 59.");

  snprintf(datestr, sizeof(datestr), "%04ld%02ld%02ld%02ld%02ld%02ldZ", yr, mo, dy, hr, mi, sc);
  return datestr;
}

/* ---------------------------------------------------------- *
 * check_ext_presence() check if extension test_ext exists in *
 * the certificate 'cert'. Returns '1' if found, '0' if not.  *
 * -----------------------------------------------------------*/
int check_ext_presence(X509_EXTENSION *test_ext, X509 *cert) {
  X509_CINF *cert_inf = NULL;
  STACK_OF(X509_EXTENSION) *list = NULL;
  ASN1_OBJECT *test_obj;
  int i, test_nid;

  /* ---------------------------------------------------------- *
   * Extract the certificate's extensions                       *
   * ---------------------------------------------------------- */
  cert_inf = cert->cert_info;
  list = cert_inf->extensions;

  if (list == NULL) return (0);
  if (sk_X509_EXTENSION_num(list) <= 0) return (0);

  test_obj = X509_EXTENSION_get_object(test_ext);
  test_nid = OBJ_obj2nid(test_obj);

  for (i=0; i<sk_X509_EXTENSION_num(list); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext;

    ext = sk_X509_EXTENSION_value(list, i);
    obj = X509_EXTENSION_get_object(ext);

    if (test_nid == (OBJ_obj2nid(obj))) return (1);
  }
  ASN1_OBJECT_free(test_obj);
  return (0);
}
