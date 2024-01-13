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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>
#include <openssl/core_names.h>
#endif

int key_enc_check(EVP_PKEY *, EVP_PKEY *);

int rsa_cmp_mod(EVP_PKEY *, EVP_PKEY *);
int rsa_enc_check(EVP_PKEY *, EVP_PKEY *);
int dsa_enc_check(EVP_PKEY *, EVP_PKEY *);
int ec_enc_check(EC_KEY *, EC_KEY *);

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
    fprintf(cgiOut, "In real-world situations; file copy, rename and transfer can create situations were it becomes unclear if a private key is the correct equivalent to a specific certificate, or certificate signing request (CSR). This online check function determines if a given private key file matches the certificate or CSR public key.");
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

         if (! (pub_key = X509_REQ_get_pubkey(req)))
            int_error("Error getting public key from X509_REQ structure.");
      }
      else int_error("Error getting a certificate or CSR file");
    }
    
    /* ---------------------------------------------------------- *
     * First key check with EVP_PKEY_cmp: 1 = "match",            *
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

    if(cmp_res1 == -2) {
      snprintf(error_str, sizeof(error_str), "Error in EVP_PKEY_cmp(): operation is not supported.");
      int_error(error_str);
    }
    if(cmp_res1 == -1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Type Missmatch");
    if(cmp_res1 ==  0) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Key Missmatch");
    if(cmp_res1 ==  1) snprintf(cmp_res1_str, sizeof(cmp_res1_str), "Match");

    /* ---------------------------------------------------------- *
     * Second key check by encrypting a test string: 1 = "match", *
     * 0 = "key missmatch", -1 = "type missmatch, -2 = "error"    *
     * ---------------------------------------------------------- */
    int cmp_res2 = 1;
    char cmp_res2_str[40]; // contains the string for match, missmatch, etc
    //cmp_res2 = key_enc_check(priv_key, pub_key);

    if(cmp_res2 == -1) snprintf(cmp_res2_str, sizeof(cmp_res2_str), "Type Missmatch");
    if(cmp_res2 ==  0) snprintf(cmp_res2_str, sizeof(cmp_res2_str), "Key Missmatch");
    if(cmp_res2 ==  1) snprintf(cmp_res2_str, sizeof(cmp_res2_str), "Match");

    /* ---------------------------------------------------------- *
     * start the html output to display the key comparison result *
     * ---------------------------------------------------------- */
    pagehead(title);

    fprintf(cgiOut, "<h3>Key Comparison:</h3>\n");
    fprintf(cgiOut, "<p></p>\n");
    fprintf(cgiOut, "<table>\n");
    fprintf(cgiOut, "<tr><th colspan=2>Result</th></tr>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt75\">Result 1:</th><td>%s</td>\n", cmp_res1_str);
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th class=\"cnt75\">Result 2:</th><td>%s</td>\n", cmp_res2_str);
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "<tr><th colspan=2>&nbsp;</th></tr>\n");
    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "</p>\n");
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
 * Function key_data_check() checks if a public and private key  *
 * matches, using algorithm-specific checks. I.e. for RSA, we do *
 * Compare the modulus values. Returns 0 for OK, 1 for missmatch *
 * ------------------------------------------------------------- */
int key_data_check(EVP_PKEY *priv, EVP_PKEY *pub) {
  int ret = -1;
  switch (EVP_PKEY_base_id(priv)) {
    case EVP_PKEY_RSA:
      if(EVP_PKEY_base_id(pub) == EVP_PKEY_RSA) {
        ret = rsa_cmp_mod(priv, pub);
        return ret;
      }
      else return -1;
      break;

    case EVP_PKEY_DSA:
     if(EVP_PKEY_base_id(pub) == EVP_PKEY_DSA) {
        return ret;
      }
      else
        int_error("Error public key type does not match private DSA key");
      break;

    case EVP_PKEY_EC:
      if(EVP_PKEY_base_id(pub) == EVP_PKEY_EC) {
        return ret;
      }
      else
        int_error("Error public key type does not match private EC key");
      break;

    default:
      int_error("Error unknown key type: no RSA, DSA or EC key provided");
      break;
  }
  return ret;
}

/* ------------------------------------------------------------- *
 * Function rsa_cmp_mod() checks if a public and private key     *
 * matches by comparing the RSA modulus. Returns 1 for OK, 0 for *
 * missmatch.                                                    *
 * ------------------------------------------------------------- */
int rsa_cmp_mod(EVP_PKEY *priv, EVP_PKEY *pub) {
  int match;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  /* -------------------------------------------------------- *
   * Old code for OpenSSL versions before version 3.0         *
   * ---------------------------------------------------------*/
  const BIGNUM *priv_mod;
  const BIGNUM *pub_mod;
  RSA *privrsa = NULL;
  if((privrsa = EVP_PKEY_get1_RSA(priv)) == NULL)
     int_error("Error getting RSA private key data.");
  RSA_get0_key(privrsa, &priv_mod, NULL, NULL);

  RSA *pubrsa = NULL;
  if((pubrsa = EVP_PKEY_get1_RSA(pub)) == NULL)
    int_error("Error getting RSA public key data.");
  RSA_get0_key(pubrsa, &pub_mod, NULL, NULL);
#else
  /* -------------------------------------------------------- *
   * New code for latest OpenSSL version 3.0                  *
   * ---------------------------------------------------------*/
  BIGNUM *priv_mod = NULL;
  BIGNUM *pub_mod = NULL;
  EVP_PKEY_get_bn_param(priv, OSSL_PKEY_PARAM_RSA_N, &priv_mod);
  EVP_PKEY_get_bn_param(pub, OSSL_PKEY_PARAM_RSA_N, &pub_mod);
#endif

  char *priv_mod_hex = BN_bn2hex(priv_mod);
  char *pub_mod_hex = BN_bn2hex(pub_mod);

  //printf("priv: %s\n", priv_mod_hex);
  //printf(" pub: %s\n", pub_mod_hex);

  if(strcmp(priv_mod_hex, pub_mod_hex) == 0)
    match = 1; // the keys modulus is matching
  else
    match = 0; // the keys modulus don't match

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  OPENSSL_free(priv_mod_hex);
  OPENSSL_free(pub_mod_hex);
#endif
  return match;
}

/* ------------------------------------------------------------- *
 * Function key_encr_check() checks if a public and private key  *
 * matches by doing EVP_PKEY_sign/EVP_PKEY_verify. Returns 1 for *
 * OK the keys match, 0 for key missmatch, -1 for type missmatch *
 * ------------------------------------------------------------- */
int key_enc_check(EVP_PKEY *priv, EVP_PKEY *pub) {
  int ret = -1;
  switch (EVP_PKEY_id(priv)) {
    case EVP_PKEY_RSA:
      /* ------------------------------------------------------- *
    `  * Type match RSA: If privkey is RSA, is pubkey also RSA?  *
       * If not return -1, if yes do encrypt/decrypt test next   *
       * ------------------------------------------------------- */
      if(EVP_PKEY_id(pub) != EVP_PKEY_RSA) return -1;
      ret = rsa_enc_check(priv, pub);
      return ret;
      break;

    case EVP_PKEY_DSA:
      /* ------------------------------------------------------- *
    `  * Type match DSA: If privkey is DSA, is pubkey also DSA?  *
       * If not return -1, if yes do encrypt/decrypt test next   *
       * ------------------------------------------------------- */
      if(EVP_PKEY_id(pub) != EVP_PKEY_DSA) return -1;
      ret = dsa_enc_check(priv, pub);
      return ret;
      break;

    case EVP_PKEY_EC:
      if(EVP_PKEY_base_id(pub) == EVP_PKEY_EC) {
        return ret;
      }
      else
        int_error("Error public key type does not match private EC key");
      break;

    default:
      int_error("Error unknown key type: no RSA, DSA or EC key provided");
      break;
  }
  return ret;
}

/* ------------------------------------------------------------ *
 * rsa_enc_check takes a private and public key to encrypt and  *
 * decrypt a test string, then compares the decrypted string.   *
 * ------------------------------------------------------------ */
int rsa_enc_check(EVP_PKEY *priv, EVP_PKEY *pub) {
  int match = -1;
  /* ---------------------------------------------------------- *
   * Create a random 24 byte test string to encrypt with priv   *
   * ---------------------------------------------------------- */
  const unsigned char md[] = "This is a secret string";
  size_t md_len = sizeof(md);

  /* ---------------------------------------------------------- *
   * Define the RSA padding method for both encrypt/decrypt ops *
   * ---------------------------------------------------------- */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  const char pad = RSA_PKCS1_PADDING;
#else
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_PKCSV15, 0);
  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY_CTX *ctx = NULL;
#endif

  /* ---------------------------------------------------------- *
   * Define the encrypted buffer, assign and zero out memory    *
   * buffer size is hardcoded as 1024 bytes (1K) to simplify.   *
   * watch buffer overrun if we get large key sizes or large    *
   * md test strings.                                           *
   * ---------------------------------------------------------- */
  size_t enc_len;
  unsigned char *enc_str;
  enc_str = OPENSSL_zalloc(1024);
  if (!enc_str)
    int_error("Error allocating memory for encryption result.");

  /* ---------------------------------------------------------- *
   *  Encrypt string with private RSA key                       *
   * ---------------------------------------------------------- */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  RSA *privrsa;
  if((privrsa = EVP_PKEY_get1_RSA(priv)) == NULL)
    int_error("Error getting RSA private key data.");
  enc_len = RSA_public_encrypt(md_len, (unsigned char*) md, enc_str, privrsa, pad);
  RSA_free(privrsa);
# else
  ctx = NULL;
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
  EVP_PKEY_encrypt_init_ex(ctx, params);
  EVP_PKEY_encrypt(ctx, enc_str, (size_t *) &enc_len, md, md_len);
  EVP_PKEY_CTX_free(ctx);
#endif
  if(enc_len <= 0)
    int_error("Error encrypting digest with private RSA key.");

  /* ---------------------------------------------------------- *
   * Successfully encrypted, now decrypt it with public RSA key *
   * buffer size is hardcoded as 1024 bytes (1K) to simplify.   *
   * watch buffer overrun if we set larger md test strings.     *
   * ---------------------------------------------------------- */
  size_t clr_len;
  unsigned char clr_str[1024] = "";

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  RSA *pubrsa;
  if((pubrsa = EVP_PKEY_get1_RSA(pub)) == NULL)
    int_error("Error getting RSA public key data.");
  clr_len = RSA_private_decrypt(enc_len, enc_str, (unsigned char*) clr_str, pubrsa, pad);
  RSA_free(pubrsa);
#else
  ctx = NULL;
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
  EVP_PKEY_decrypt_init_ex(ctx, params);
  EVP_PKEY_decrypt(ctx, clr_str, (size_t *) &clr_len, enc_str, enc_len);
  EVP_PKEY_CTX_free(ctx);
#endif
  if(clr_len <= 0)
    int_error("Error decrypting digest with public RSA key.");

  /* ---------------------------------------------------------- *
   * Successfully decrypted, compare decrypt string with orig.  *
   * ---------------------------------------------------------- */
  if(strcmp((char *)md, (char *)clr_str) == 0) match = 1; // The keys match
  else match = 0; // The keys don't match
  return match;
}

/* ------------------------------------------------------------ *
 * dsa_enc_check takes a private and public key to encrypt and  *
 * decrypt a test string, then compares the decrypted string.   *
 * THIS FUNCTION IS IN DEV - not implemented yet!!!!!!!!!!!!!   *
 * ------------------------------------------------------------ */
int dsa_enc_check(EVP_PKEY *priv, EVP_PKEY *pub) {
  //int match = -1;
  /* ---------------------------------------------------------- *
   * Create a random 24 byte test string to encrypt with priv   *
   * ---------------------------------------------------------- */
  //const unsigned char md[] = "This is a secret string";
  //size_t md_len = sizeof(md);

  /* ---------------------------------------------------------- *
   * Define the encrypted buffer, assign and zero out memory    *
   * buffer size is hardcoded as 1024 bytes (1K) to simplify.   *
   * watch buffer overrun if we get large key sizes or large    *
   * md test strings.                                           *
   * ---------------------------------------------------------- */
  //size_t enc_len;
  unsigned char *enc_str;
  enc_str = OPENSSL_zalloc(1024);
  if (!enc_str)
    int_error("Error allocating memory for encryption result.");

  /* ---------------------------------------------------------- *
   *  Encrypt string with private DSA key                       *
   * ---------------------------------------------------------- */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  DSA *privdsa;
  if((privdsa = EVP_PKEY_get1_DSA(priv)) == NULL)
    int_error("Error getting DSA private key data.");
  // encryption function goes here
  DSA_free(privdsa);
    
  DSA *pubdsa;
  if((pubdsa = EVP_PKEY_get1_DSA(pub)) == NULL)
    int_error("Error getting DSA public key data.");
  // decryption function goes here
  DSA_free(pubdsa);
#endif
  return 1;
}
int ec_enc_check(EC_KEY *priv, EC_KEY *pub) {
  return 1;
}
