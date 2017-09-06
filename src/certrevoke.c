/* ---------------------------------------------------------- *
 * file:        certrevoke.c                                  *
 * purpose:     revokes a cert, put it on the revokation list *
 * hint:        call with ?cfilename=xxx?certkey=yyy          *
 *              needs cert privkey (PEM) to authorize.        *
 * -----------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "webcert.h"

int cgiMain() {

   char                 formkey[REQLEN]   = "";
   char 		certfilepath[255] = "";
   char                 certnamestr[81]   = "";
   char 		certfilestr[81]   = "[n/a]";
   FILE 		*certfile         = NULL;
   char 		title[41]         = "Certificate Revocation";

/* ---------------------------------------------------------- *
 * These function calls are essential to make many PEM +      *
 * other openssl functions work.                              *
 * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();

/* ---------------------------------------------------------- *
 * process the CGI calling arguments                          *
 * ---------------------------------------------------------- */
   if (! (cgiFormString("cfilename", certfilestr, sizeof(certfilestr)) == cgiFormSuccess))
      int_error("Error getting >cfilename< from calling form");

/* ------------------------------------------------------------ *
 * Since we access a file, we make sure no "../../.." is passed *
 * from the calling URL, else sensitive files could be read and *
 * we have a security problem. We reject occurrences of '..' '/'*
 * ------------------------------------------------------------ */
   if ( strstr(certfilestr, "..") ||
        strchr(certfilestr, '/')  ||
        (! strstr(certfilestr, ".pem")) )
      int_error("Error incorrect data in >cfilename<");

/* ---------------------------------------------------------- *
 * check if its the CA cert, or open the requested filename   *
 * -----------------------------------------------------------*/
   if (strcmp(certfilestr, "cacert.pem") == 0) {
      if (! (certfile = fopen(CACERT, "r")))
         int_error("Error can't open CA certificate file");
      strncpy(title, "Display Root CA Certificate", sizeof(title));
   } else {
      snprintf(certfilepath, sizeof(certfilepath), "%s/%s", CACERTSTORE,
		      						certfilestr);
      if (! (certfile = fopen(certfilepath, "r")))
         int_error("Error cant open Certificate file");
   }

/* ---------------------------------------------------------- *
 * strip off the file format extension from the file name     *
 * -----------------------------------------------------------*/
   strncpy(certnamestr, certfilestr, sizeof(certnamestr));
   strtok(certnamestr, ".");

/* ---------------------------------------------------------- *
 * decode the certificate                                     *
 * -----------------------------------------------------------*/
  X509 *cert;
  if (! (cert = PEM_read_X509(certfile,NULL,NULL,NULL)))
    int_error("Error loading cert into memory");

/* ---------------------------------------------------------- *
 * Check if we already got the key, otherwise we ask for it   *
 * -----------------------------------------------------------*/
  if (! (cgiFormString("certkey", formkey, KEYLEN) == cgiFormSuccess )) {

    pagehead(title);
    fprintf(cgiOut, "<h3>Revoke the following certificate</h3>\n");
    fprintf(cgiOut, "<hr />\n");
    if (strcmp(certfilestr, "cacert.pem") == 0) {
      display_cert(cert, "WebCert Root CA", "wct_chain", -1);
    }
    else {
     display_cert(cert, "Server/System/Application", "wct_chain", -1);
    }
    fprintf(cgiOut, "<p></p>\n");

    fprintf(cgiOut, "<h3>Authorize the revocation by submitting the certficate private key</h3>\n");
    fprintf(cgiOut, "<hr />\n");
    fprintf(cgiOut, "<form action=\"certrevoke.cgi\" method=\"post\">");
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
     fprintf(cgiOut, "<th colspan=\"2\">");
    fprintf(cgiOut, "Please paste the matching certificate's private key into the ");
    fprintf(cgiOut, "field below (PEM format):");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<td class=\"getcert\" colspan=\"2\">\n");
    fprintf(cgiOut, "<textarea name=\"certkey\" cols=\"64\" rows=\"13\">");
    fprintf(cgiOut, "</textarea>");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>&nbsp;</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "<p></p>\n");
  
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
    fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
    fprintf(cgiOut, "<input type=\"submit\" value=\"Revoke Certificate\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
  } 
  else {
  /* ---------------------------------------------------------- *
   * We got the cert and a key, now check if the key matches.   *
   * First, check if a key was pasted with the BEGIN and END    *
   * lines, assuming the key data in between is intact          *
   * ---------------------------------------------------------- */
    key_validate_PEM(formkey);

  /* ---------------------------------------------------------- *
   * input seems OK, writing key to a temp mem BIO and load it  *
   * ---------------------------------------------------------- */
    BIO *keybio  = NULL;
    keybio = BIO_new_mem_buf(formkey, -1);

    EVP_PKEY *priv_key = NULL;
    if (! (priv_key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL)))
      int_error("Error loading certificate private key content");

  /* ---------------------------------------------------------- *
   * Extract the public key from a certificate                  *
   * ---------------------------------------------------------- */
    EVP_PKEY *pub_key = NULL;
    if ((pub_key = X509_get_pubkey(cert)) == NULL)
      int_error("Error getting public key from certificate");

  /* ---------------------------------------------------------- *
   * First key check with EVP_PKEY_cmp: 1 = "match",            *
   * 0 = "key missmatch", -1 = "type missmatch, -2 = "error"    *
   * ---------------------------------------------------------- */
    char cmp_res1_str[40]; // contains the string for match, missmatch, etc
    int cmp_res1;
    cmp_res1 = EVP_PKEY_cmp(priv_key, pub_key);

    if(cmp_res1 == -2) {
      snprintf(error_str, sizeof(error_str), "Error in EVP_PKEY_cmp(): operation is not supported.");
      int_error(error_str);
    }
    if(cmp_res1 == -1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Type Missmatch");
    if(cmp_res1 ==  0) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Key Missmatch");
    if(cmp_res1 ==  1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Match");

    if(cmp_res1 !=  1) {
    /* ---------------------------------------------------------- *
     * Decline unauthorized - the key did not match               *
     * -----------------------------------------------------------*/
      pagehead(title);
      fprintf(cgiOut, "<h3>Unable to revoke the certificate: %s</h3>\n", cmp_res1_str);
      fprintf(cgiOut, "<hr />\n");
      if (strcmp(certfilestr, "cacert.pem") == 0) {
        display_cert(cert, "WebCert Root CA", "wct_chain", -1);
      }
      else {
       display_cert(cert, "Server/System/Application", "wct_chain", -1);
      }
      fprintf(cgiOut, "<p></p>\n");
      fprintf(cgiOut, "<form action=\"certrevoke.cgi\" method=\"post\">\n");
      fprintf(cgiOut, "<table>\n");
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>");
      fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
      fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
      fprintf(cgiOut, "<input type=\"submit\" value=\"Revoke Certificate\" />\n");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");
      fprintf(cgiOut, "</table>\n");
      fprintf(cgiOut, "</form>\n");
    }
    else {
    /* ---------------------------------------------------------- *
     * Revocation authorized - add cert to index.txt database     *
     * -----------------------------------------------------------*/
      const char indexfile[]  = INDEXFILE;
      // do the add here ...

    /* ---------------------------------------------------------- *
     * Revocation authorized - create + publish the new CRL file  *
     * -----------------------------------------------------------*/
     cgi_gencrl(CRLFILE);

    /* ---------------------------------------------------------- *
     * Revocation authorized - confirm revocation to html output  *
     * -----------------------------------------------------------*/
      pagehead(title);
      fprintf(cgiOut, "<h3>Revoked certificate: %s</h3>\n", certfilestr);
      fprintf(cgiOut, "<hr />\n");

      if (fopen(CRLFILE, "r")) {
         X509_CRL *crl = NULL;
         crl = cgi_load_crlfile(CRLFILE);
         fprintf(cgiOut, "<p></p>\n");
         fprintf(cgiOut, "<h3>CA Certificate Revocation List:</h3>\n");
         fprintf(cgiOut, "<hr />\n");
         display_crl(crl);
      }

    }
  }

  pagefoot();
  return(0);
}
