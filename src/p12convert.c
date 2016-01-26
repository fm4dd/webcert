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

int cgiMain() {

/* ---------------------------------------------------------- *
 * These function calls are essential to make many PEM + other*
 * OpenSSL functions work.                                    *
 * ---------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
   ERR_load_BIO_strings();

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
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "Step 1\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your certificate (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"file\" name=\"certfile\" />\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: The certificates private key file for PKCS12 conversion");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "Step 2\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your certificate private key (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"file\" name=\"keyfile\" >\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Optional: The certificates signing CA file(s) can also be included in the PKCS12 bundle");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "Step 3\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload the signing CA file (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"file\" name=\"calist\" />\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: Passphrase to protect the PKCS12 file");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th style=\"width: 50px;\">\n");
    fprintf(cgiOut, "Step 4\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Passphrase can be up to 40 chars");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"password\" name=\"p12pass\" class=\"p12pass\"/>\n");
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
    fprintf(cgiOut, "Required: The certificate for PKCS12 conversion");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "Step 1\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your PKCS12 file (.pfx or .p12 extensions)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"file\" name=\"p12file\" />\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Required: Passphrase to read the PKCS12 file");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th style=\"width: 50px;\">\n");
    fprintf(cgiOut, "Step 2\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Passphrase can be up to 40 chars");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"password\" name=\"p12pass\" class=\"p12pass\"/>\n");
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
       * Get the PKCS12 part-1: get the certificate file name       *
       * ---------------------------------------------------------- */
      char cert_name[1024] = "";
      ret = cgiFormFileName("certfile", cert_name, sizeof(cert_name));
      if (ret !=cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Could not get the certificate file, return code %d", ret);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-1: get the certificate file size       *
       * ---------------------------------------------------------- */
      int cert_fsize = 0;
      cgiFormFileSize("certfile", &cert_fsize);
      if (cert_fsize == 0) int_error("The uploaded certificate file is empty (0 bytes)");
      if (cert_fsize > REQLEN) {
        snprintf(error_str, sizeof(error_str), "The uploaded certificate file greater %d bytes", REQLEN);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-1: we open the file and get a handle   * 
       * ---------------------------------------------------------- */
      cgiFilePtr certfile_ptr = NULL;
      if (cgiFormFileOpen("certfile", & certfile_ptr) != cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Cannot open the uploaded certificate file %s", cert_name);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-1: read the file content in a buffer   *
       * ---------------------------------------------------------- */
      char cert_form[REQLEN] = "";
      if (! (cgiFormFileRead(certfile_ptr, cert_form, REQLEN, &cert_fsize) == cgiFormSuccess)) {
        snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded certificate file %s", cert_name);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-1: get the cert into the X509 struct   *
       * ---------------------------------------------------------- */
      BIO *certbio = NULL;
      certbio = BIO_new_mem_buf(cert_form, -1);

      X509 *cert = NULL;
      if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        snprintf(error_str, sizeof(error_str), "Error reading cert structure of %s into memory", cert_name);
        int_error(error_str);
      }
      BIO_free(certbio);

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-2: get the private key file name       *
       * ---------------------------------------------------------- */
      char key_name[1024] = "";
      ret = cgiFormFileName("keyfile", key_name, sizeof(key_name));
      if (ret !=cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Could not get the private key file, return code %d", ret);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-2: get the private key file size       *
       * ---------------------------------------------------------- */
      int key_fsize = 0;
      cgiFormFileSize("keyfile", &key_fsize);
      if (key_fsize == 0) int_error("The uploaded key file is empty (0 bytes)");
      if (key_fsize > KEYLEN) {
        snprintf(error_str, sizeof(error_str), "The uploaded key file greater %d bytes", KEYLEN);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-2: we open the file to get the handle  *
       * ---------------------------------------------------------- */
      cgiFilePtr keyfile_ptr = NULL;
      if (cgiFormFileOpen("keyfile", &keyfile_ptr) != cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Cannot open the uploaded private key file %s", key_name);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-2: read the file content in a buffer   *
       * ---------------------------------------------------------- */
      char key_form[REQLEN] = "";
      if (! (cgiFormFileRead(keyfile_ptr, key_form, REQLEN, &key_fsize) == cgiFormSuccess)) {
        snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded private key file %s", key_name);
        int_error(error_str);
      }

      /* ---------------------------------------------------------- *
       * Get the PKCS12 part-2: get the key into the EVP_KEY struct *
       * ---------------------------------------------------------- */
      BIO *keybio  = NULL;
      keybio = BIO_new_mem_buf(key_form, -1);

      EVP_PKEY *priv_key = NULL;
      if (! (priv_key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL))) {
        snprintf(error_str, sizeof(error_str), "Error reading private key structure of %s into memory", key_name);
        int_error(error_str);
      }
      BIO_free(keybio);

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
      fprintf(cgiOut, "The PKCS12 certificate bundle %s.p12 for download", p12name);
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th width=\"75px\">");
      fprintf(cgiOut, "PKCS12 URL:</th>");
      fprintf(cgiOut, "<td>");
      fprintf(cgiOut, "<a href=\"http://%s%s/tmp/%s\">",
                      cgiServerName, CERTEXPORTURL, p12name);
      fprintf(cgiOut, "http://%s%s/tmp/%s</a>\n",
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
      fprintf(cgiOut, "<th width=\"75px\">File Size:</th>\n");
      fprintf(cgiOut, "<td>%d Bytes</td>\n", p12_fsize);
      fprintf(cgiOut, "</tr>\n");

      if (p12->version) {
        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th width=\"75px\">Version:</th>\n");
        fprintf(cgiOut, "<td>%ld (3 == PKCS#12 v1.1)</td>\n",
                        ASN1_INTEGER_get(p12->version));
        fprintf(cgiOut, "</tr>\n");
      }

      /* P12 using password integrity mode? */
      if (p12->mac) {
        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th width=\"75px\">Auth Mode:</th>\n");
        fprintf(cgiOut, "<td>Password</td>\n");
        fprintf(cgiOut, "</tr>\n");

        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th width=\"75px\">MAC Algorithm:</th>\n");
        char buf[1024];
        OBJ_obj2txt(buf, 1024, p12->mac->dinfo->algor->algorithm, 0);
        fprintf(cgiOut, "<td>%s</td>\n", buf);
        fprintf(cgiOut, "</tr>\n");

        fprintf(cgiOut, "<tr>\n");
        fprintf(cgiOut, "<th width=\"75px\">MAC Iteration:</th>\n");
        fprintf(cgiOut, "<td>%ld (Compatibility: 1, OpenSSL Default: 2048, WIndows 7 Default: 2000)</td>\n",
                        p12->mac->iter ? ASN1_INTEGER_get(p12->mac->iter) : 1);
        fprintf(cgiOut, "</tr>\n");

       //OBJ_obj2txt(buf, 1024, p12->mac->dinfo->algor->parameter->type, 0);
       // fprintf(cgiOut, "<tr>\n");
       // fprintf(cgiOut, "<th width=\"75px\">MAC Digest:</th>\n");
       //BIO *outbio;
       //outbio = BIO_new(BIO_s_file());
       //outbio = BIO_new_fp(cgiOut, BIO_NOCLOSE);
       //M_ASN1_OCTET_STRING_print(bio, p12->mac->salt);
       //M_ASN1_OCTET_STRING_print(outbio, p12->mac->dinfo->digest);
       //BIO_free(bio);
       // fprintf(cgiOut, "<td>%s</td>\n", buf);
       // fprintf(cgiOut, "</tr>\n");
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
    display_cert(cert, "Server/System/Application", "wct_chain", -1);
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
 * Function display_stack shows all certs of a STACK_OF(X509) *
 * ---------------------------------------------------------- */
void display_stack(STACK_OF(X509) *ca) {
  int certnum = sk_X509_num(ca);
  unsigned int counter = 0;
  X509 *cert;

  for(counter=0; counter<certnum; counter++) {
    cert = sk_X509_value(ca, counter);
    if (certnum == 1) display_cert(cert, "CA Chain", "wct_chain", -1);
    else display_cert(cert, "CA Chain", "wct_chain", counter);
    fprintf(cgiOut, "<p></p>\n");
    X509_free(cert);
  }
}
