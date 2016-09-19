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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "webcert.h"

int cgiMain() {
   BIO *outbio = NULL;
   X509 *cert  = NULL;
   char formreq[REQLEN] = "";
   char formkey[KEYLEN] = "";
   static char  title[] = "Certificate Renewal";

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  add_missing_ev_oids();

  outbio = BIO_new(BIO_s_file());
  BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * check if cert data was handed to certverify.cgi,           *
   * or if someone called us directly without a request         *
   * -----------------------------------------------------------*/
   if (! (cgiFormString("cert-renew", formreq, REQLEN) == cgiFormSuccess ))
         int_error("Error no certificate data received from certstore.cgi");

  /* ---------------------------------------------------------- *
   * Is the cert data plausible or is it garbage?               *
   * ---------------------------------------------------------- */
   // cert_validate(formreq);

  /* ---------------------------------------------------------- *
   * input seems OK, write the request to a temporary mem BIO   *
   * ---------------------------------------------------------- */
   BIO *certbio  = NULL;
   certbio = BIO_new_mem_buf(formreq, -1);

  /* ---------------------------------------------------------- *
   * Try to read the PEM request with openssl lib functions     *
   * ---------------------------------------------------------- */
   if(! (cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL)))
      int_error("Error cant read request content with PEM function");

  /* ---------------------------------------------------------- *
   * Check if we also got the key, otherwise we must ask for it *
   * -----------------------------------------------------------*/
   if (! (cgiFormString("cert-key", formkey, KEYLEN) == cgiFormSuccess )) {

    /* ---------------------------------------------------------- *
     * Display the cert data, and provide the key input field     *
     * ---------------------------------------------------------- */
     pagehead(title);

     display_cert(cert, "Server/System/Application", "wct_chain", -1);
     fprintf(cgiOut, "<p></p>");

     fprintf(cgiOut, "<form action=\"certrenew.cgi\" method=\"post\">");
     fprintf(cgiOut, "<table>\n");
     fprintf(cgiOut, "<tr>\n");
     fprintf(cgiOut, "<th colspan=\"2\">");
     fprintf(cgiOut, "Please paste the matching certificate's private key into the ");
     fprintf(cgiOut, "field below (PEM format):");
     fprintf(cgiOut, "</th>\n");
     fprintf(cgiOut, "</tr>\n");
 
     fprintf(cgiOut, "<tr>\n");
     fprintf(cgiOut, "<td class=\"getcert\" colspan=\"2\">\n");
     fprintf(cgiOut, "<textarea name=\"cert-key\" cols=\"64\" rows=\"13\">");
     fprintf(cgiOut, "</textarea>");
     fprintf(cgiOut, "</td>\n");
     fprintf(cgiOut, "</tr>\n");

     fprintf(cgiOut, "<tr>\n");
     fprintf(cgiOut, "<th colspan=\"2\">");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cert-renew\" value=\"");
     PEM_write_bio_X509(outbio, cert);
     fprintf(cgiOut, "\">\n");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Create CSR\" />\n");
     fprintf(cgiOut, "</th>\n");
     fprintf(cgiOut, "</tr>\n");
     fprintf(cgiOut, "</table>\n");

     fprintf(cgiOut, "<p></p>\n");
     keycreate_input();

     fprintf(cgiOut, "</form>");

     pagefoot();
  } // end if cert-key is missing
  else {
    /* ---------------------------------------------------------- *
     * We got the cert and a key, try to create a CSR from here.  *
     * First, check if a key was pasted with the BEGIN and END    *
     * lines, assuming the key data in between is intact          *
     * ---------------------------------------------------------- */
    key_validate_PEM(formkey);

    /* ---------------------------------------------------------- *
     * input seems OK, writing key to a temp mem BIO and load it  *
     * ---------------------------------------------------------- */
    BIO *keybio  = NULL;
    keybio = BIO_new_mem_buf(formkey, -1);

    EVP_PKEY *pkey = NULL;
    if (! (pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL)))
      int_error("Error loading certificate private key content");

    /* ---------------------------------------------------------- *
     * Set digest: sha256 for RSA, dss for DSA, ecdsa for ECC key *
     * ---------------------------------------------------------- */
    EVP_MD const *digest = NULL;

    switch (pkey->type) {
      case EVP_PKEY_RSA: digest = EVP_sha256(); break;
      case EVP_PKEY_DSA: digest = EVP_dss(); break;
      case EVP_PKEY_EC: digest = EVP_ecdsa(); break;
      default:
        int_error("Unknown/unsupported key type, not RSA, DSA, or ECC  type");
        break;
    }

    /* ---------------------------------------------------------- *
     * Convert the old certificate +key into a new CSR request    *
     * ---------------------------------------------------------- */
    X509_REQ *certreq = NULL;
    if ((certreq = X509_to_X509_REQ(cert, pkey, digest)) == NULL) 
      int_error("Can't convert certificate and key intoa new CSR equest.");

    /* ---------------------------------------------------------- *
     * Add the following types of existing cert extensions to the *
     * CSR: SAN, Basic Constraints, Key Usage, Extended Key Usage *
     * -----------------------------------------------------------*/
    STACK_OF(X509_EXTENSION) *ext_list = NULL;
    X509_CINF *cert_inf = cert->cert_info;

    /* if there are any cert exts */
    if ((ext_list = cert_inf->extensions) != NULL) {
      STACK_OF(X509_EXTENSION) *csr_list = NULL;
      int copy_ext[4] = { NID_subject_alt_name, NID_key_usage,
                          NID_basic_constraints, NID_ext_key_usage };
      int i;

      /* cycle through all cert exts */
      for (i = 0; i < sk_X509_EXTENSION_num(ext_list); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(ext_list, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

        /* Check if ext is supposed to be copied */
        int j = 0;
        while(j < 4) {
          if (copy_ext[j] == OBJ_obj2nid(obj)) {
            if (X509v3_add_ext(&csr_list, ext, -1) == NULL) int_error("Error adding csr ext");
            break;
          }
          j++;
        } //end while  
      } // end cycle through extensions
      /* ---------------------------------------------------------- *
       * add the new CSR extension list to the CSR                  * 
       * ---------------------------------------------------------- */
      if (csr_list) X509_REQ_add_extensions(certreq, csr_list); 
      /* ---------------------------------------------------------- *
       * Because we added data to the CSR, we re-do the signature   *
       * ---------------------------------------------------------- */
      if (!X509_REQ_sign(certreq,pkey,digest))
         int_error("Error signing X509_REQ structure with digest.");
    }

    /* ---------------------------------------------------------- *
     * display the CSR data, and link to the certsign CGI         *
     * -----------------------------------------------------------*/
    pagehead(title);

    display_csr(certreq);
    fprintf(cgiOut, "<p></p>\n");

    display_signing(certreq);

    pagefoot();
    BIO_free(keybio);
  }
  BIO_free(certbio);
  BIO_free(outbio);
  return(0);
}
