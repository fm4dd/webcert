/* -------------------------------------------------------------------------- *
 * file:         p12convert.c                                              *
 * purpose:      Converts any certificate, its private key, and any optional  *
 *               CA certificates into a PKCS12 encoded file bundle, good for  *
 *               easy import into various systems. After the conversion, we   *
 *               put the PKCS12 file into the "export" directory and provide  *
 *               a download link to the PKCS12 file. We don't keep this file  *
 *               stored for long, and delete any file older than 1 hour by    *
 *               cron.                                                        *
 * -------------------------------------------------------------------------- */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include "webcert.h"

/* ---------------------------------------------------------- *
 * This function is taken from openssl/crypto/asn1/t_x509.c.  *
 * ---------------------------------------------------------- */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);

/* ---------------------------------------------------------- *
 * display_cert() shows certificate details in a HTML table.  *
 * ---------------------------------------------------------- */
void display_p12(PKCS12 *p12, char *pass);
void display_stack(STACK_OF(X509) *ca);
void display_bags(STACK_OF(PKCS12_SAFEBAG) *bags, int i);

int cgiMain() {

/* ---------------------------------------------------------- *
 * These function calls are essential to make many PEM + other*
 * OpenSSL functions work.                                    *
 * ---------------------------------------------------------- */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  // OpenSSL v3.0 now loads error strings automatically:
  // https://www.openssl.org/docs/manmaster/man7/migration_guide.html
#else
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
#endif

  /* ---------------------------------------------------------- *
   * If called w/o arguments, display the data gathering form.  *
   * ---------------------------------------------------------- */
  char **form_data = NULL;  /* query data string array */
  if (cgiFormEntries(&form_data) != cgiFormSuccess)
    int_error("Error: Could not retrieve CGI form data.");

  if(form_data[0] == NULL) {

    static char title[] = "PKCS12 Converter - Data Entry";
  /* ---------------------------------------------------------- *
   * start the html form for data entry                         *
   * -----------------------------------------------------------*/
    pagehead(title);

    fprintf(cgiOut, "<h3>Convert certificates into a new PKCS12 file</h3>\n");
    fprintf(cgiOut, "<hr />\n");
    fprintf(cgiOut, "<p>\n");
    fprintf(cgiOut, "Build a new PKCS12 file from local certs.\n");
    fprintf(cgiOut, "</p>\n");

    fprintf(cgiOut, "<form enctype=\"multipart/form-data\" action=\"p12convert.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: The certificate for PKCS12 conversion");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "Step 1");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your certificate (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"file\" name=\"certfile\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: The certificates private key file for PKCS12 conversion");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "Step 2");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your certificate private key (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"file\" name=\"keyfile\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Optional: The certificates signing CA file(s) can also be included in the PKCS12 bundle");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "Step 3");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload the signing CA file (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"file\" name=\"calist\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: Passphrase to protect the PKCS12 file");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "Step 4");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Passphrase can be up to 40 chars");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"password\" name=\"p12pass\" class=\"p12pass\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">\n");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"cmd\" value=\"create\" />\n");
    fprintf(cgiOut, "<input type=\"reset\" value=\"Clear All\" />\n");
    fprintf(cgiOut, "&nbsp;");
    fprintf(cgiOut, "<input type=\"submit\" value=\"Generate\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "</form>\n");
    fprintf(cgiOut, "<p></p>\n");

    fprintf(cgiOut, "<h3>Analyze and display the content of a PKCS12 file</h3>\n");
    fprintf(cgiOut, "<hr />\n");
    fprintf(cgiOut, "<p>\n");
    fprintf(cgiOut, "Take a PKCS12 file and display what is inside.\n");
    fprintf(cgiOut, "</p>\n");

    fprintf(cgiOut, "<form enctype=\"multipart/form-data\" action=\"p12convert.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: The PKCS12 file for analysis");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "Step 1");
    fprintf(cgiOut, "</th class=\"cnt\">\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your PKCS12 file (.pfx or .p12 extensions)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"file\" name=\"p12file\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: Passphrase to read the PKCS12 file");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "Step 2");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Passphrase can be up to 40 chars");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"password\" name=\"p12pass\" class=\"p12pass\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">\n");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"cmd\" value=\"analyze\" />\n");
    fprintf(cgiOut, "<input type=\"reset\" value=\"Clear All\" />\n");
    fprintf(cgiOut, "&nbsp;");
    fprintf(cgiOut, "<input type=\"submit\" value=\"Analyze\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "</form>\n");

    pagefoot();
    return(0);
  }
  else {
  /* ---------------------------------------------------------- *
   * Called with 'cmd' args, should be "create" or "analyze"    *
   * -----------------------------------------------------------*/
    int ret = 0;
    char cmd[8] = "";
    char error_str[4096] = "";

    /* ---------------------------------------------------------- *
     * Check the 'cmd' arg is having valid content                *
     * ---------------------------------------------------------- */
    if (cgiFormString("cmd", cmd, sizeof(cmd)) == cgiFormSuccess) {
      if (! ( (strcmp(cmd, "create") == 0) ||
              (strcmp(cmd, "analyze") == 0) ) )
         int_error("Error URL >cmd< parameter is not [create|analyze]");
    }
    else int_error("Error getting the >cmd< parameter in URL");

    /* ---------------------------------------------------------- *
     * If the 'cmd' arg asks to create a new PKCS12               *
     * ---------------------------------------------------------- */
    if (strcmp(cmd, "create") == 0) {
      static char      title[] = "PKCS12 Converter - PKCS12 Creation";

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-1: get the certificate                 *
       * ---------------------------------------------------------- */
      X509 *cert = NULL;
      char cert_name[1024] = "";

      ret = cgiFormFileName("certfile", cert_name, sizeof(cert_name));
      if (ret !=cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Could not get the certificate file %s, return code %d", cert_name, ret);
        int_error(error_str);
      }
      cert = cgi_load_certfile(cert_name);

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-2: get the private key                 *
       * ---------------------------------------------------------- */
      EVP_PKEY *priv_key = NULL;
      char key_name[1024] = "";

      ret = cgiFormFileName("keyfile", key_name, sizeof(key_name));
      if (ret !=cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Could not get the private key file, return code %d", ret);
        int_error(error_str);
      }
      priv_key = cgi_load_keyfile(key_name);

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-3: get the signing certs file name     *
       * This is optional, so no error if it doesn't exist          *
       * ---------------------------------------------------------- */
      STACK_OF(X509) *ca_chain = NULL;
      char calist_name[1024] = "";

      ret = cgiFormFileName("calist", key_name, sizeof(calist_name));
      if (ret == cgiFormSuccess) {
        /* ---------------------------------------------------------- *
         * Get the PKCS12 part-3: get the signing certs file size     *
         * ---------------------------------------------------------- */
        int calist_fsize = 0;
        cgiFormFileSize("calist", &calist_fsize);
        if (calist_fsize == 0) int_error("The uploaded CA file list is empty (0 bytes)");
        if (calist_fsize > CALISTLEN) {
          snprintf(error_str, sizeof(error_str), "The uploaded CA list file is greater %d bytes", CALISTLEN);
          int_error(error_str);
        }

        /* ---------------------------------------------------------- *
         * Get the PKCS12 part-3: we open the file to get the handle  *
         * ---------------------------------------------------------- */
        cgiFilePtr cafile_ptr = NULL;
        if (cgiFormFileOpen("calist", &cafile_ptr) != cgiFormSuccess) {
          snprintf(error_str, sizeof(error_str), "Cannot open the uploaded CA list file %s", calist_name);
          int_error(error_str);
        }

        /* ---------------------------------------------------------- *
         * Get the PKCS12 part-3: read the file content in a buffer   *
         * ---------------------------------------------------------- */
        char  ca_form[CALISTLEN] = "";
        if (! (cgiFormFileRead(cafile_ptr, ca_form, CALISTLEN, &calist_fsize) == cgiFormSuccess)) {
          snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded CA list file %s", calist_name);
          int_error(error_str);
        } 

        /* ---------------------------------------------------------- *
         * Get the PKCS12 part-3: load the CA's into a STACK_OF(X509) *
         * ---------------------------------------------------------- */
        STACK_OF(X509_INFO) *list = sk_X509_INFO_new_null();
        BIO *cabio  = NULL;
        cabio = BIO_new_mem_buf(ca_form, -1);

        /* load the buffer data in a STACK_OF(X509_INFO) struct */
        if (! (list = PEM_X509_INFO_read_bio(cabio, NULL, NULL, NULL))) {
          snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded CA list file %s", calist_name);
          int_error(error_str);
        }
        BIO_free(cabio);

        /* check if we got no or only usable CA certificates */
        int ca_count = sk_X509_INFO_num(list);
        if (ca_count == 0) {
          snprintf(error_str, sizeof(error_str), "No Signing certificates found in CA list file %s", calist_name);
          int_error(error_str);
        }

        /* convert STACK_OF(X509_INFO) to STACK_OF(X509), see  */
        /* also add_certs_from_file() in openssl/apps/crl2p7.c */
        ca_chain = sk_X509_new_null();
        int i;

        for (i = 0; list && i < sk_X509_INFO_num(list); i++) {
          X509_INFO *stack_item = sk_X509_INFO_value(list, i);
          ret = sk_X509_push(ca_chain, stack_item->x509);
        }
        // freeing the stack below results in a crash
        //sk_X509_INFO_pop_free(list, X509_INFO_free);
      } // end if CA list file was provided

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-4: get the PKCS12 passphrase           *
       * ---------------------------------------------------------- */
      char p12pass[P12PASSLEN] = "";
      if (! (cgiFormString("p12pass", p12pass, sizeof(p12pass)) == cgiFormSuccess)) {
         int_error("Error retrieving mandatory PKCS12 passphrase.");
      }

      /* ---------------------------------------------------------- *
       * Create the PKCS12 structure, values of zero use defaults   *
       * we could change the cipher, e.g. set nid_cert to           *
       * NID_pbe_WithSHA1And3_Key_TripleDES_CBC                     *
       * ---------------------------------------------------------- */
      PKCS12 *p12;
      int iter = PKCS12_DEFAULT_ITER;
      int maciter = PKCS12_DEFAULT_ITER;

      if ((p12 = PKCS12_new()) == NULL)
        int_error("Error creating PKCS12 structure.\n");

          snprintf(error_str, sizeof(error_str), "Error building PKCS12 structure with ca list %d", sk_X509_num(ca_chain));
      if(! (p12 = PKCS12_create( p12pass,     // certbundle access password
                           cert_name,   // friendly certname
                           priv_key,    // the certificate private key
                           cert,        // the main certificate
                           ca_chain,    // stack of CA cert chain
                           0,           // int nid_key (default 3DES)
                           0,           // int nid_cert (40bitRC2)
                           iter,        // int iter (default 2048)
                           maciter,     // int maciter (default 1)
                           0 ))) {      // int keytype (default no flag)
          int_error("Error creating PKCS12 structure.\n");
        }

      /* ---------------------------------------------------------- *
       * Create the PKCS12 temporary .p12 filename, based on time   *
       * ---------------------------------------------------------- */
      char p12filestr[81] = "";
      char p12name[41] = "";
      time_t now;
      // Get current time
      time(&now);

      snprintf(p12name, sizeof(p12name), "%ld.p12", (long) now);
      snprintf(p12filestr, sizeof(p12filestr), "%s/tmp/%s", CERTEXPORTDIR, p12name);

      /* ---------------------------------------------------------- *
       * Write the PKCS12 structure to the .p12 file                *
       * ---------------------------------------------------------- */
      FILE *p12file = NULL;
      if (! (p12file=fopen(p12filestr, "w")))
        int_error("Error open temporary PKCS12 file for writing.\n");

      int bytes = 0;
      bytes = i2d_PKCS12_fp(p12file, p12);
      if (bytes <= 0)
        int_error("Error writing data to the temporary PKCS12 file.\n");

      /* ---------------------------------------------------------- *
       * Now we close and free objects used during PKCS12 creation  *
       * ---------------------------------------------------------- */
      fclose(p12file);
      X509_free(cert);
      EVP_PKEY_free(priv_key);
      sk_X509_pop_free(ca_chain, X509_free);

      /* ---------------------------------------------------------- *
       * start the html output to display the PKCS12 download link  *
       * ---------------------------------------------------------- */
      pagehead(title);
      fprintf(cgiOut, "<table>\n");
      fprintf(cgiOut, "<th colspan=\"2\">");
      fprintf(cgiOut, "The PKCS12 certificate bundle %s for download", p12name);
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th  class=\"cnt75\">");
      fprintf(cgiOut, "PKCS12 URL:</th>");
      fprintf(cgiOut, "<td>");
      fprintf(cgiOut, "<a href=\"%s://%s%s/tmp/%s\">", HTTP_TYPE,
                      cgiServerName, CERTEXPORTURL, p12name);
      fprintf(cgiOut, "%s://%s%s/tmp/%s</a>\n", HTTP_TYPE,
                   cgiServerName, CERTEXPORTURL, p12name);
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th colspan=\"2\">\n");
      fprintf(cgiOut, "<form action=\"p12convert.cgi\" method=\"post\">\n");
      fprintf(cgiOut, "<input type=\"submit\" value=\"Return\" />\n");
      fprintf(cgiOut, "</form>\n");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");
      fprintf(cgiOut, "</table>\n");
      fprintf(cgiOut, "<p></p>\n");

      display_p12(p12, p12pass);
      pagefoot();
      PKCS12_free(p12);
    } // end if 'cmd' arg is "create"
    /* ---------------------------------------------------------- *
     * If the 'cmd' arg asks to analyze an existing PKCS12        *
     * ---------------------------------------------------------- */
    else if (strcmp(cmd, "analyze") == 0) {

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-5: get the pkcs12 file name            *
       * ---------------------------------------------------------- */
      char p12_name[1024] = "";
      ret = cgiFormFileName("p12file", p12_name, sizeof(p12_name));
      if (ret !=cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Could not get the PKCS12 file, return code %d", ret);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-5: get the pkcs12 file size            *
       * ---------------------------------------------------------- */
      int p12_fsize = 0;
      cgiFormFileSize("p12file", &p12_fsize);
      if (p12_fsize == 0) int_error("The uploaded PKCS12 file is empty (0 bytes)");
      if (p12_fsize > CALISTLEN) {
        snprintf(error_str, sizeof(error_str), "The uploaded PKCS12 file greater %d bytes", CALISTLEN);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-5: we open the file and get a handle   *
       * ---------------------------------------------------------- */
      cgiFilePtr p12file_ptr = NULL;
      if (cgiFormFileOpen("p12file", & p12file_ptr) != cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Cannot open the uploaded PKCS12 file %s", p12_name);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-5: read the file content in a buffer   *
       * ---------------------------------------------------------- */
      char p12_form[CALISTLEN] = "";
      if (! (cgiFormFileRead(p12file_ptr, p12_form, CALISTLEN, &p12_fsize) == cgiFormSuccess)) {
        snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded PKCS12 file %s", p12_name);
        int_error(error_str);
      }
      cgiFormFileClose(p12file_ptr);

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-5: get the file into the PKCS12 struct *
       * ---------------------------------------------------------- */
      BIO *p12bio = NULL;
      p12bio = BIO_new_mem_buf(p12_form, p12_fsize);

      PKCS12 *p12 = NULL;
      if (! (p12 = d2i_PKCS12_bio(p12bio, NULL))) {
        snprintf(error_str, sizeof(error_str), "Error reading PKCS12 structure of %s into memory", p12_name);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get and check the PKCS12 passphrase                        *
       * ---------------------------------------------------------- */
      char p12pass[P12PASSLEN] = "";
      if (! (cgiFormString("p12pass", p12pass, sizeof(p12pass)) == cgiFormSuccess)) {
         int_error("Error retrieving mandatory PKCS12 passphrase.");
      }

      if (! (ret = PKCS12_verify_mac(p12,p12pass,strlen(p12pass)))){
         int_error("Error wrong PKCS12 passphrase.");
      }

      static char title[] = "PKCS12 Converter - PKCS12 Data Extract";
      /* ---------------------------------------------------------- *
       * start the html output to display the PKCS12 data           *
       * -----------------------------------------------------------*/
      pagehead(title);

      fprintf(cgiOut, "<table>\n");
      fprintf(cgiOut, "<th colspan=\"2\">");
      fprintf(cgiOut, "PKCS12 File Information for %s", p12_name);
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th class=\"cnt75\">File Size:</th>\n");
      fprintf(cgiOut, "<td>%d Bytes</td>\n", p12_fsize);
      fprintf(cgiOut, "</tr>\n");

      // Since OpenSSL 1.1.0 we can't access the objects directly
      // and there is not get function for the version. OpenSSL
      // hardcodes the version to 3 in crypto/pkcs12/p12_init.c 
      //if (p12->version) {
      //  fprintf(cgiOut, "<tr>\n");
      //  fprintf(cgiOut, "<th class=\"cnt75\">Version:</th>\n");
      //  fprintf(cgiOut, "<td>%ld (3 == PKCS#12 v1.1)</td>\n",
      //                  ASN1_INTEGER_get(p12->version));
      //  fprintf(cgiOut, "</tr>\n");
      //}

      /* P12 using password integrity mode? */
      if (PKCS12_mac_present(p12)) {
         const X509_ALGOR *pmacalg = NULL;
	 const ASN1_OCTET_STRING *psalt = NULL;
	 const ASN1_INTEGER *piter = NULL;
         PKCS12_get0_mac(NULL, &pmacalg, &psalt, &piter, p12);

        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th  class=\"cnt75\">Auth Mode:</th>\n");
        fprintf(cgiOut, "<td>Password</td>\n");
        fprintf(cgiOut, "</tr>\n");

        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th class=\"cnt75\">MAC Algorithm:</th>\n");
        char buf[1024];
        OBJ_obj2txt(buf, 1024, pmacalg->algorithm, 0);
        fprintf(cgiOut, "<td>%s</td>\n", buf);
        fprintf(cgiOut, "</tr>\n");

        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th class=\"cnt75\">MAC Iteration:</th>\n");
        fprintf(cgiOut, "<td>%ld (Compatibility: 1, OpenSSL Default: 2048, Windows 7 Default: 2000)</td>\n",
                        ASN1_INTEGER_get(piter));
        fprintf(cgiOut, "</tr>\n");

        STACK_OF(PKCS7) *asafes = NULL;
        STACK_OF(PKCS12_SAFEBAG) *bags;
        int i, bagnid;
        PKCS7 *p7;

        asafes = PKCS12_unpack_authsafes(p12);
        for (i = 0; i < sk_PKCS7_num(asafes); i++) {
          p7 = sk_PKCS7_value (asafes, i);
          bagnid = OBJ_obj2nid (p7->type);

          // check if the p7 bag is NOT encrypted
          if (bagnid == NID_pkcs7_data) {
            fprintf(cgiOut, "<tr>\n");
            fprintf(cgiOut, "<th class=\"cnt75\">PKCS7 - #%d</th>\n", i);
            fprintf(cgiOut, "<td>Content: PKCS7 Data</td>\n");
            fprintf(cgiOut, "</tr>\n");
            bags = PKCS12_unpack_p7data(p7);
          } // end if(bagnid == NID_pkcs7_data)

          // check if the p7 bag is encrypted
          if (bagnid == NID_pkcs7_encrypted) {
            fprintf(cgiOut, "<tr>\n");
            fprintf(cgiOut, "<th class=\"cnt75\">PKCS7  - #%d</th>\n", i);
            fprintf(cgiOut, "<td>Content: PKCS7 Encrypted Data ");
            OBJ_obj2txt(buf, 1024, p7->d.encrypted->enc_data->algorithm->algorithm, 0);
            fprintf(cgiOut, "%s</td>\n", buf);
            fprintf(cgiOut, "</tr>\n");
            bags = PKCS12_unpack_p7encdata(p7,p12pass,strlen(p12pass));
          } // end if(bagnid == NID_pkcs7_encrypted)

        display_bags(bags, i);
        sk_PKCS12_SAFEBAG_pop_free (bags, PKCS12_SAFEBAG_free);
        } // end for loop
        if (asafes) sk_PKCS7_pop_free (asafes, PKCS7_free);
      }

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th colspan=\"2\">&nbsp;</th>\n");
      fprintf(cgiOut, "</tr>\n");
      fprintf(cgiOut, "</table>\n");
      fprintf(cgiOut, "<p></p>\n");

      display_p12(p12, p12pass);

      pagefoot();
    } // end if 'cmd' arg is "analyze"
    return(0);
  } // end if form data wasnt empty
} // end main

/* ---------------------------------------------------------- *
 *  Function display_p12 extracts and displays PKCS12 data    *
 * ---------------------------------------------------------- */
void display_p12(PKCS12 *p12, char *pass) {
  int ret = 0;
  char error_str[4096] = "";
  EVP_PKEY *pkey;
  X509 *cert;
  STACK_OF(X509) *ca;

  ret = PKCS12_parse(p12, pass, &pkey, &cert, &ca);
  if (ret == 0) {
    snprintf(error_str, sizeof(error_str), "Error extracting cert, key or CA data from PKCS12 struct");
    int_error(error_str);
  }

  /* level -1 switch of the level display in the cert table header */
  if (cert != NULL) {
    display_cert(cert, "Server/System/Application", "app_cert", -1);
    fprintf(cgiOut, "<p></p>\n");
  }
  else {
    fprintf(cgiOut, "<p>This PKCS12 file carries no certificate.</p>\n");
  }

  if (pkey != NULL) {
    display_key(pkey);
    fprintf(cgiOut, "<p></p>\n");
  }
  else {
    fprintf(cgiOut, "<p>This PKCS12 file carries no private key file.</p>\n");
  }

  if (ca != NULL) {
    display_stack(ca);
    fprintf(cgiOut, "<p></p>\n");
  }
  else {
    fprintf(cgiOut, "<p>This PKCS12 file carries no signing certificate chain.</p>\n");
  }
}
/* ---------------------------------------------------------- *
 *  Function display_bag extracts and displays PKCS7 bag info *
 * ---------------------------------------------------------- */
void display_bags(STACK_OF(PKCS12_SAFEBAG) *bags, int j) {
  int k;
  for (k=0; k < sk_PKCS12_SAFEBAG_num (bags); k++) {
    PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value (bags, k);
    fprintf(cgiOut, "<tr>\n");
    switch (M_PKCS12_bag_type(bag)) {
      case NID_keyBag:
        fprintf(cgiOut, "<th class=\"cnt75\">Bag - #%d</th>\n", k);
        fprintf(cgiOut, "<td>Key Bag</td>\n");
        // TODO: print bag attributes, see openssl/apps/pkcs12.c
        //print_attribs (out, bag->attrib, "Bag Attributes");
      break;
      case NID_pkcs8ShroudedKeyBag:
        fprintf(cgiOut, "<th class=\"cnt75\">Bag - #%d</th>\n", k);
        // TODO: print bag algorithm and attributes, see openssl/apps/pkcs12.c
        //fprintf(cgiOut, "<td>Shrouded Key Bag %s, Attributes: </td>\n", bag->value.shkeybag->algor);
        fprintf(cgiOut, "<td>PKCS8 Shrouded Key Bag</td>\n");
      break;
      case NID_certBag:
        fprintf(cgiOut, "<th class=\"cnt75\">Bag - #%d</th>\n", k);
        fprintf(cgiOut, "<td>Certificate Bag</td>\n");
      break;
      case NID_safeContentsBag:
        fprintf(cgiOut, "<th class=\"cnt75\">Bag - #%d</th>\n", k);
        fprintf(cgiOut, "<td>Safe Contents Bag</td>\n");
      break;
    }
    fprintf(cgiOut, "</tr>\n");
  }
}

/* ---------------------------------------------------------- *
 * Function display_stack shows all certs of a STACK_OF(X509) *
 * ---------------------------------------------------------- */
void display_stack(STACK_OF(X509) *ca) {
  int certnum = sk_X509_num(ca);
  unsigned int counter = 0;
  X509 *cert;

  for(counter=0; counter<certnum; counter++) {
    cert = sk_X509_value(ca, counter);
    if (certnum == 1) display_cert(cert, "Root CA", "ca_cert", -1);
    else display_cert(cert, "CA Chain", "wct_chain", counter);
    fprintf(cgiOut, "<p></p>\n");
    X509_free(cert);
  }
}
