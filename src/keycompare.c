/* -------------------------------------------------------------------------- *
 * file:         keycompare.c                                                 *
 * purpose:      Checks if a given private key belongs to a given certificate *
 *               or certificate signing request (CSR)                         *
 *                                                                            *
 * Note: Using OpenSSL EVP_PKEY_cmp() function to check a private key against *
 * a cert or CSR public key does not catch the case when the private key is   *
 * not matching the public key, because only both sides pubkeys are compared. *
 * TODO: implement a a hash/de-hash function to confirm private / public keys *
 * TODO: re-use/globalize the cgi_load_cert and cgi_load_csr functions        *
 * -------------------------------------------------------------------------- */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "webcert.h"

char error_str[4096] = "";

X509 * cgi_load_cert(char *);
X509_REQ * cgi_load_csr(char *);

int cgiMain() {
/* ---------------------------------------------------------- *
 * These function calls are essential to make many PEM + other*
 * OpenSSL functions work.                                    *
 * ---------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
   ERR_load_BIO_strings();

  static char title[] = "Key Checker";

  /* ---------------------------------------------------------- *
   * If called w/o arguments, display the data gathering form.  *
   * ---------------------------------------------------------- */
  char **form_data = NULL;  /* query data string array */
  if (cgiFormEntries(&form_data) != cgiFormSuccess)
    int_error("Error: Could not retrieve CGI form data.");

  if(form_data[0] == NULL) {

  /* ---------------------------------------------------------- *
   * start the html form for data entry                         *
   * -----------------------------------------------------------*/
    pagehead(title);

    fprintf(cgiOut, "<h3>Compare a private key is matching the certificate or CSR</h3>\n");
    fprintf(cgiOut, "<hr />\n");
    fprintf(cgiOut, "<p>\n");
    fprintf(cgiOut, "In real-world situations; file copy, rename and transfer can create situations were it becomes unclear if a private key is the correct equivalent to a specific certificate, or certificate siging request (CSR). This online check function determines if a given private key file matches the certificate or CSR public key.");
    fprintf(cgiOut, "</p><p>\n");
    fprintf(cgiOut, "Provide the private key:\n");
    fprintf(cgiOut, "</p>\n");

    fprintf(cgiOut, "<form enctype=\"multipart/form-data\" action=\"keycompare.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "The private key file in unencrypted PEM format");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload the private key (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"file\" name=\"keyfile\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">\n");
    fprintf(cgiOut, "&nbsp;");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");

    fprintf(cgiOut, "<p>\n");
    fprintf(cgiOut, "Provide the certificate or CSR to compare against:\n");
    fprintf(cgiOut, "</p>\n");

    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "The certificate to check the key against");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"crt_cb\" value=crt checked onclick=\"switchGrey('crt_cb', 'crt_td', 'csr_td', 'none');\" />");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload the certificate (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"crt_td\">");
    fprintf(cgiOut, "<input type=\"file\" name=\"certfile\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "The certificate signing request (CSR) to check against");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt\">");
    fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"csr_cb\" value=csr onclick=\"switchGrey('csr_cb', 'csr_td', 'crt_td', 'none');\" />");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload the CSR (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td  class=\"type\" id=\"csr_td\">");
    fprintf(cgiOut, "<input type=\"file\" name=\"csrfile\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">\n");
    fprintf(cgiOut, "<input type=\"reset\" value=\"Clear All\" />\n");
    fprintf(cgiOut, "&nbsp;");
    fprintf(cgiOut, "<input type=\"submit\" value=\"Compare\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "</form>\n");

    pagefoot();
    return(0);
  }
  else {
    /* ---------------------------------------------------------- *
     * Called with form data, need a key and a cert or CSR file   *
     * -----------------------------------------------------------*/
    int ret = 0;

    /* ---------------------------------------------------------- *
     * Get the private key file name                              *
     * ---------------------------------------------------------- */
    char key_name[1024] = "";
    ret = cgiFormFileName("keyfile", key_name, sizeof(key_name));
    if (ret !=cgiFormSuccess) {
      snprintf(error_str, sizeof(error_str), "Could not get the private key file, return code %d", ret);
      int_error(error_str);
    }

    /* ---------------------------------------------------------- *
     * Get the private key file size                              *
     * ---------------------------------------------------------- */
    int key_fsize = 0;
    cgiFormFileSize("keyfile", &key_fsize);
    if (key_fsize == 0) int_error("The uploaded key file is empty (0 bytes)");
    if (key_fsize > KEYLEN) {
      snprintf(error_str, sizeof(error_str), "The uploaded key file greater %d bytes", KEYLEN);
      int_error(error_str);
    }

    /* ---------------------------------------------------------- *
     * Open the key file to get the handle                        *
     * ---------------------------------------------------------- */
    cgiFilePtr keyfile_ptr = NULL;
    if (cgiFormFileOpen("keyfile", &keyfile_ptr) != cgiFormSuccess) {
      snprintf(error_str, sizeof(error_str), "Cannot open the uploaded private key file %s", key_name);
      int_error(error_str);
    }

    /* ---------------------------------------------------------- *
     * Load the key file content in a buffer                      *
     * ---------------------------------------------------------- */
    char key_form[REQLEN] = "";
    if (! (cgiFormFileRead(keyfile_ptr, key_form, REQLEN, &key_fsize) == cgiFormSuccess)) {
      snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded private key file %s", key_name);
      int_error(error_str);
    }

    /* ---------------------------------------------------------- *
     * Check if the key has the ----- BEGIN and ----- END         *
     * lines, assuming the key data in between is intact          *
     * ---------------------------------------------------------- */
    key_validate(key_form);

    /* ---------------------------------------------------------- *
     * Load the key into the EVP_KEY struct                       *
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
     * Check if we got a cert or csr file to process              *
     * ---------------------------------------------------------- */
    char file_name[1024] = "";
    EVP_PKEY *pub_key = NULL;
    X509_REQ *req = NULL;
    X509 *cert = NULL;

    ret = cgiFormFileName("certfile", file_name, sizeof(file_name));
    if (ret == cgiFormSuccess) {
      /* ---------------------------------------------------------- *
       * Extract the public key from a certificate                  *
       * ---------------------------------------------------------- */
        cert = cgi_load_cert(file_name);

        if ((pub_key = X509_get_pubkey(cert)) == NULL)
          int_error("Error getting public key from certificate");
    }
    else {
      ret = cgiFormFileName("csrfile", file_name, sizeof(file_name));
      if (ret == cgiFormSuccess) {
        /* ---------------------------------------------------------- *
         * We extract the public key from a CSR file                  *
         * ---------------------------------------------------------- */
        req = cgi_load_csr(file_name);

        if ( (req->req_info == NULL) ||
             (req->req_info->pubkey == NULL) ||
             (req->req_info->pubkey->public_key == NULL) ||
             (req->req_info->pubkey->public_key->data == NULL))
                int_error("Error missing public key in request");

        if ((pub_key=EVP_PKEY_new()) == NULL)
           int_error("Error creating EVP_PKEY structure.");

        if ((pub_key=X509_REQ_get_pubkey(req)) == NULL)
           int_error("Error unpacking public key from request");
      }
      else int_error("Error getting a certificate or CSR file");
    }
    
    /* ---------------------------------------------------------- *
     * The actual key check is here: 1 = match, 0 = missmatch     *
     * ---------------------------------------------------------- */
    char cmp_result[40]; // either "match", "key missmatch", "type missmatch"
    ret = EVP_PKEY_cmp(priv_key, pub_key);
    if(ret == -2) {
      snprintf(error_str, sizeof(error_str), "Error in the key comparison function: operation is not supported.");
      int_error(error_str);
    }
    if(ret == -1) snprintf(cmp_result, sizeof(cmp_result), "Type Missmatch");
    if(ret ==  0) snprintf(cmp_result, sizeof(cmp_result), "Key Missmatch");
    if(ret ==  1) snprintf(cmp_result, sizeof(cmp_result), "Match");

    /* ---------------------------------------------------------- *
     * start the html output to display the PKCS12 download link  *
     * ---------------------------------------------------------- */
    pagehead(title);

    fprintf(cgiOut, "<h3>Key Comparison Result: %s</h3>\n", cmp_result);
    fprintf(cgiOut, "<hr />\n");
    fprintf(cgiOut, "<p>\n");
    fprintf(cgiOut, "WebCert checked if the following key:\n");
    fprintf(cgiOut, "</p>\n");

    display_key(priv_key);
    fprintf(cgiOut, "<p>\n");
    if(cert) fprintf(cgiOut, "is matching to the certificate public key below:\n");
    if(req) fprintf(cgiOut, "is matching to the CSR public key below:\n");
    fprintf(cgiOut, "</p>\n");
    if(cert) display_cert(cert, "", "wct_chain", -1);
    if(req) display_csr(req);

    pagefoot();
    return(0);
  } // end if form data wasn't empty
} // end main

/* ------------------------------------------------------------- *
 * Function cgi_load_cert() loads a CGI form called "certfile"   *
 * into a X509 struct.                                           *
 * ------------------------------------------------------------- */
X509 * cgi_load_cert(char* file) {
X509 *crt = NULL;
  /* ---------------------------------------------------------- *
   * Get the certificate file size                              *
   * ---------------------------------------------------------- */
  int cert_fsize = 0;
  cgiFormFileSize("certfile", &cert_fsize);
  if (cert_fsize == 0) int_error("The uploaded certificate file is empty (0 bytes)");
  if (cert_fsize > REQLEN) {
    snprintf(error_str, sizeof(error_str), "The uploaded certificate file greater %d bytes", REQLEN);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Open the certfile and get a handle                         *
   * ---------------------------------------------------------- */
  cgiFilePtr certfile_ptr = NULL;
  if (cgiFormFileOpen("certfile", & certfile_ptr) != cgiFormSuccess) {
    snprintf(error_str, sizeof(error_str), "Cannot open the uploaded certificate file %s", file);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Read the certificate file content in a buffer              *
   * ---------------------------------------------------------- */
  char cert_form[REQLEN] = "";
  if (! (cgiFormFileRead(certfile_ptr, cert_form, REQLEN, &cert_fsize) == cgiFormSuccess)) {
    snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded certificate file %s", file);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Load the cert into the X509 struct                         *
   * ---------------------------------------------------------- */
  BIO *certbio = NULL;
  certbio = BIO_new_mem_buf(cert_form, -1);

  if (! (crt = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    snprintf(error_str, sizeof(error_str), "Error reading cert structure of %s into memory", file);
    int_error(error_str);
  }
  BIO_free(certbio);
  return crt;
}

/* ------------------------------------------------------------- *
 * Function cgi_load_csr() loads a CGI form called "csrfile"     *
 * into a X509_REQ struct.                                       *
 * ------------------------------------------------------------- */
X509_REQ * cgi_load_csr(char *file) {
X509_REQ *csr = NULL;
  /* ---------------------------------------------------------- *
   * Get the certificate file size                              *
   * ---------------------------------------------------------- */
  int csr_fsize = 0;
  cgiFormFileSize("csrfile", &csr_fsize);
  if (csr_fsize == 0) int_error("The uploaded certificate file is empty (0 bytes)");
  if (csr_fsize > REQLEN) {
    snprintf(error_str, sizeof(error_str), "The uploaded CSR file is greater %d bytes", REQLEN);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Open the certificate request file and get a handle         *
   * ---------------------------------------------------------- */
  cgiFilePtr csrfile_ptr = NULL;
  if (cgiFormFileOpen("csrfile", & csrfile_ptr) != cgiFormSuccess) {
    snprintf(error_str, sizeof(error_str), "Cannot open the uploaded certificate file %s", file);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Read the certificate request file content in a buffer      *
   * ---------------------------------------------------------- */
  char csr_form[REQLEN] = "";
  if (! (cgiFormFileRead(csrfile_ptr, csr_form, REQLEN, &csr_fsize) == cgiFormSuccess)) {
    snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded CSR file %s", file);
    int_error(error_str);
  }

 /* ---------------------------------------------------------- *
  * check if a CSR was pasted or if someone just sends garbage *
  * ---------------------------------------------------------- */
  csr_validate(csr_form);

  /* ---------------------------------------------------------- *
   * input seems OK, write the request to a temporary BIO buffer*
   * -----------------------------------------------------------*/
  BIO *csrbio = NULL;
  csrbio = BIO_new_mem_buf(csr_form, -1);

 /* ---------------------------------------------------------- *
  * Try to read the PEM request with openssl lib functions     *
  * ---------------------------------------------------------- */
  if (! (csr = PEM_read_bio_X509_REQ(csrbio, NULL, 0, NULL))) {
    snprintf(error_str, sizeof(error_str), "Error reading csr structure of %s into memory", file);
    int_error(error_str);
  }
  BIO_free(csrbio);
  return csr;
}
