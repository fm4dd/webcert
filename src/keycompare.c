/* -------------------------------------------------------------------------- *
 * file:         keycompare.c                                                 *
 * purpose:      Checks if a given private key belongs to a given certificate *
 *               or certificate signing request (CSR)                         *
 *                                                                            *
 * Note: Using OpenSSL EVP_PKEY_cmp() function to check a private key against *
 * a cert or CSR public key does not catch the case when the private key is   *
 * not matching the public key, because only both sides pubkeys are compared. *
 * -------------------------------------------------------------------------- */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "webcert.h"

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
     * Get the private key file                                   *
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
        cert = cgi_load_certfile(file_name);

        if ((pub_key = X509_get_pubkey(cert)) == NULL)
          int_error("Error getting public key from certificate");
    }
    else {
      ret = cgiFormFileName("csrfile", file_name, sizeof(file_name));
      if (ret == cgiFormSuccess) {
        /* ---------------------------------------------------------- *
         * We extract the public key from a CSR file                  *
         * ---------------------------------------------------------- */
        req = cgi_load_csrfile(file_name);

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

//    ret = key_encrypt_check(priv_key, pub_key);

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
