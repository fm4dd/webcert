/* ---------------------------------------------------------- *
 * file:        certrevoke.c                                  *
 * purpose:     revokes a cert, put it on the revokation list *
 * hint:        call with ?cfilename=xxx?certkey=yyy          *
 *              needs cert privkey (PEM) to authorize.        *
 * -----------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "webcert.h"

/* OpenSSL-defined CRL revocation reason strings */
static const char *crl_reasons[] = {
    /* CRL reason strings */
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    /* Additional pseudo reasons */
    "holdInstruction",
    "keyTime",
    "CAkeyTime"
};


int check_index(X509 *x509, CA_DB *db);
int do_revoke(X509 *x509, CA_DB *db, const char *value);

int cgiMain() {

  char formkey[REQLEN]   = "";
  char certfilepath[255] = "";
  char certnamestr[81]   = "";
  char certfilestr[81]   = "[n/a]";
  FILE *certfile         = NULL;
  char title[41]         = "Certificate Revocation";

/* ---------------------------------------------------------- *
 * These function calls are essential to make many PEM +      *
 * other openssl functions work.                              *
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

    fprintf(cgiOut, "<h3>Authorize revocation with the certificate private key, or revocation master key</h3>\n");
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
  
   /* ---------------------------------------------------------- *
    * Display the table to select a revocation reason from list  *
    * -----------------------------------------------------------*/
    fprintf(cgiOut, "<p></p>\n");
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"4\">");
    fprintf(cgiOut, "Select the appropriate revocation reason</th>");
    fprintf(cgiOut, "<tr>");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"radio\" id=\"rsa_rb\" name=\"crl_reason\" value=\"%d\" checked />%s</td>\n", 0, crl_reasons[0]);

    int i;
    for (i = 1; i < 8; i++) { // crl_reasons has 8 core entries
      fprintf(cgiOut, "<td>");
      fprintf(cgiOut, "<input type=\"radio\" id=\"rsa_rb\" name=\"crl_reason\" value=\"%d\" />%s</td>\n", i, crl_reasons[i]);

      if (i == 3) fprintf(cgiOut, "</tr>\n<tr>");
    }

    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"4\">");
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
   * Extract the public key from the certificate                *
   * ---------------------------------------------------------- */
    EVP_PKEY *pub_key = NULL;
    if ((pub_key = X509_get_pubkey(cert)) == NULL)
      int_error("Error getting public key from certificate");

  /* ---------------------------------------------------------- *
   * 1st try: check key against cert. EVP_PKEY_cmp: 1 = "match" *
   * 0 = "key missmatch", -1 = "type missmatch, -2 = "error"    *
   * ---------------------------------------------------------- */
    char cmp_res1_str[40]; // contains the string for match, missmatch, etc
    int cmp_res1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL v3.0 changed EVP_PKEY_cmp() to EVP_PKEY_eq():
    // https://www.openssl.org/docs/manmaster/man7/migration_guide.html
    cmp_res1 = EVP_PKEY_eq(priv_key, pub_key);
#else
    cmp_res1 = EVP_PKEY_cmp(priv_key, pub_key);
#endif

    if(cmp_res1 == -2) int_error("Cert key problem in EVP_PKEY_cmp(): operation is not supported");
    if(cmp_res1 == -1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Cert key type missmatch");
    if(cmp_res1 ==  1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Cert key authorized");

    /* ---------------------------------------------------------- *
     * If the given private key did not match the cert pubkey, do *
     * 2nd try: see if the key matches the global revocation key  *
     * -----------------------------------------------------------*/
    if(cmp_res1 == 0) {
      BIO *revbio = BIO_new(BIO_s_file());
      if ((revbio == NULL) || (BIO_read_filename(revbio, REVOKEY) <= 0))
        int_error("Error reading revocation key file");

      EVP_PKEY *revo_key = NULL;
      if (! (revo_key = PEM_read_bio_PUBKEY(revbio, NULL, NULL, NULL)))
        int_error("Error loading revocation key content");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
      // OpenSSL v3.0 changed EVP_PKEY_cmp() to EVP_PKEY_eq():
      // https://www.openssl.org/docs/manmaster/man7/migration_guide.html
      cmp_res1 = EVP_PKEY_eq(priv_key, revo_key);
#else
      cmp_res1 = EVP_PKEY_cmp(priv_key, revo_key);
#endif

      if(cmp_res1 == -2) int_error("Revocation key problem in EVP_PKEY_cmp(): operation is not supported");
      if(cmp_res1 == -1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Revocation key type missmatch");
      if(cmp_res1 ==  1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Revocation key authorized");
      if(cmp_res1 ==  0) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Revocation key missmatch");
    }

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
     * Revocation authorized - Add cert as revoked to index.db,   *
     * create and publish a new CRL file with all revocations.    *
     * -----------------------------------------------------------*/
      CA_DB *db = NULL;
      DB_ATTR db_attr;

    /* ---------------------------------------------------------- *
     * Get the revocation reason code from the calling cgi form   *
     * ---------------------------------------------------------- */
      int reason;
      cgiFormInteger("crl_reason", &reason, 0);
      //int_error(crl_reasons[reason]);

    /* ---------------------------------------------------------- *
     * Get all revoked certificates from revocation DB index.txt  *
     * ---------------------------------------------------------- */
      if((db = load_index(INDEXFILE, &db_attr)) == NULL)
        int_error("Error cannot load CRL certificate database file");

    /* ---------------------------------------------------------- *
     * Check if the cert already has a DB entry in state revoked  *
     * ---------------------------------------------------------- */
      int exist = check_index(cert, db);

      if(exist == 0) {
      /* ---------------------------------------------------------- *
       * Create the certs DB entry, and set the status to revoked   *
       * ---------------------------------------------------------- */
        do_revoke(cert, db, crl_reasons[reason]); 

      /* ---------------------------------------------------------- *
       * Save updated list of revoked certificates to index.txt     *
       * ---------------------------------------------------------- */
        if((save_index(INDEXFILE, db)) != 1)
          int_error("Error cannot write CRL certificate database file");

      /* ---------------------------------------------------------- *
       * Create new CRL file from index.txt, overwrite the old one  *
       * -----------------------------------------------------------*/
        cgi_gencrl(CRLFILE);
      }

    /* ---------------------------------------------------------- *
     * Revocation completed - confirm revocation to html output   *
     * -----------------------------------------------------------*/
      pagehead(title);
      fprintf(cgiOut, "<h3>Successfully revoked certificate: %s</h3>\n", certfilestr);
      fprintf(cgiOut, "<hr />\n");

      if (fopen(CRLFILE, "r")) {
         X509_CRL *crl = NULL;
         crl = cgi_load_crlfile(CRLFILE);
         fprintf(cgiOut, "Updated CA Certificate Revocation List:\n");
         fprintf(cgiOut, "<p></p>\n");
         display_crl(crl);
      }
    }
  }

  pagefoot();
  return(0);
}
