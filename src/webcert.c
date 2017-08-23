/* -------------------------------------------------------------------------- *
 * file:         webcert.c                                                    *
 * purpose:      Shared functions across multiple CGI                         *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <cgic.h>
#include "webcert.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

/* ---------------------------------------------------------- *
 * csr_validate_PEM(): a basic check for the CSR's PEM format * 
 *                                                            *
 * check if a CSR was pasted with the BEGIN and END           *
 * lines, assuming the request in between is intact           *
 * ---------------------------------------------------------- */
void csr_validate_PEM(char * form) {

   /* Check if the form contains a newline character */
   if (! strchr(form, '\n'))
      int_error("Error invalid request format, received garbage line");

   /* Use a temporary buffer reqtest to modify the content */
   char reqtest[REQLEN] = "";
   strncpy(reqtest, form, REQLEN);

   /* Identify the last line */
   char endline[81] = "";
   strncpy(endline, (strrchr(reqtest, '\n')+1), 81);

   /* should there be extra newlines at file end, we remove here */
   while(strlen(endline) == 0 && strlen(reqtest) > 0) {
      reqtest[strlen(reqtest)-1] = '\0';
      strncpy(endline, (strrchr(reqtest, '\n')+1), 81);
   }

   /* Identify the first line */
   char beginline[81] = "";
   strtok(reqtest, "\n");
   strncpy(beginline, reqtest, 81);

   /* should there be a windows carriage return, we remove it here */
   char *char_pos = NULL;
   if ((char_pos = strchr(beginline, '\r'))) *char_pos='\0';
   if ((char_pos = strchr(endline, '\r'))) *char_pos='\0';

   if(! (
         (strcmp(beginline, "-----BEGIN CERTIFICATE REQUEST-----") == 0 &&
          strcmp(endline,   "-----END CERTIFICATE REQUEST-----") == 0) ||
         (strcmp(beginline, "-----BEGIN NEW CERTIFICATE REQUEST-----") == 0 &&
          strcmp(endline,   "-----END NEW CERTIFICATE REQUEST-----") == 0)
        )) {
      snprintf(error_str, sizeof(error_str), 
        "Error invalid key format, can't read BEGIN/END lines.%s%s%s%s%s",
        "<p>Beginline: ", beginline, "</p><p>Endline: ", endline, "</p>");
      int_error(error_str);
   }
}

/* ---------------------------------------------------------- *
 * key_validate_PEM(): a basic check for the Key's PEM format * 
 *                                                            *
 * check if a key was pasted with the BEGIN and END           *
 * lines, assuming the key data in between is intact.         *
 * The following line variations are expected:                *
 * -----BEGIN RSA PRIVATE KEY-----                            *
 * -----BEGIN DSA PRIVATE KEY-----                            *
 * -----BEGIN EC PRIVATE KEY-----                             *
 * -----BEGIN PRIVATE KEY-----                                *
 * ---------------------------------------------------------- */
void key_validate_PEM(char * form) {
   /* Check if the form contains a newline character */
   if (! strchr(form, '\n'))
      int_error("Error invalid key format, received garbage line.");

   /* Use a temporary buffer keytest to modify the content */
   char keytest[KEYLEN] = "";
   strncpy(keytest, form, KEYLEN);

   /* copy the last line */
   char endline[81] = "";
   strncpy(endline, (strrchr(keytest, '\n')+1), 81);

   /* should there be extra newlines at file end, we remove here */
   while (strlen(endline) == 0 && strlen(keytest) > 0) {
      keytest[strlen(keytest)-1] = '\0';
      strncpy(endline, (strrchr(keytest, '\n')+1), 81);
   }

   /* Identify the first line */
   char beginline[81] = "";
   strtok(keytest, "\n");
   strncpy(beginline, keytest, 81);

   /* should there be a windows carriage return, we remove it here */
   char *char_pos = NULL;
   if ((char_pos = strchr(beginline, '\r'))) *char_pos='\0';
   if ((char_pos = strchr(endline, '\r'))) *char_pos='\0';

   /* check for the acceptable line variations */
   if(! (
          (strcmp(beginline, "-----BEGIN RSA PRIVATE KEY-----") == 0 &&
           strcmp(endline,   "-----END RSA PRIVATE KEY-----") == 0) ||
          (strcmp(beginline, "-----BEGIN DSA PRIVATE KEY-----") == 0 &&
           strcmp(endline,   "-----END DSA PRIVATE KEY-----") == 0) ||
          (strcmp(beginline, "-----BEGIN EC PRIVATE KEY-----") == 0 &&
           strcmp(endline,   "-----END EC PRIVATE KEY-----") == 0) ||
          (strcmp(beginline, "-----BEGIN PRIVATE KEY-----") == 0 &&
           strcmp(endline,   "-----END PRIVATE KEY-----") == 0)
        )) {
      snprintf(error_str, sizeof(error_str), 
        "Error invalid key format, can't read BEGIN/END lines.%s%s%s%s%s",
        "<p>Beginline: ", beginline, "</p><p>Endline: ", endline, "</p>");
      int_error(error_str);
   }
}

/* ---------------------------------------------------------- *
 * X509_signature_dump() converts binary signature data into  *
 * hex bytes, separated with : and a newline after 54 chars.  *
 * (2 chars + 1 ':' = 3 chars, 3 chars * 18 = 54)             *
 * ---------------------------------------------------------- */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent) {
  const unsigned char *s;
  int i, n;

  n=sig->length;
  s=sig->data;
  for (i=0; i<n; i++) {
    if ((i%21) == 0) {
      if (i != 0 && BIO_write(bp,"\n",1) <= 0) return 0;
      if (BIO_indent(bp, indent, indent) <= 0) return 0;
    }
    if (BIO_printf(bp,"%02x%s",s[i],
      ((i+1) == n)?"":":") <= 0) return 0;
  }

  if (BIO_write(bp,"\n",1) != 1) return 0;

  return 1;
}

/* ---------------------------------------------------------- *
 * OpenSSL seems to lack a few OID's used for EV certificates *
 * ---------------------------------------------------------- */
void add_missing_ev_oids() {
  /* --------------------------------------------------------- *
   * OBJ_create():                                             *
   * First field is the OID, which will be converted to DER    *
   * encoding. Next are the long and short description of      *
   * this OID. The descriptions will not be included as the    *
   * extension identifier, but the DER encoding of the OID.    *
   * --------------------------------------------------------- */
  OBJ_create("1.3.6.1.4.1.311.60.2.1.1",
             "jurisdiction Of Incorporation LocalityName",
             "jurisdiction Of Incorporation LocalityName");

  OBJ_create("1.3.6.1.4.1.311.60.2.1.2",
             "jurisdiction Of Incorporation StateOrProvinceName",
             "jurisdiction Of Incorporation StateOrProvinceName");

  OBJ_create("1.3.6.1.4.1.311.60.2.1.3",
             "jurisdiction Of Incorporation CountryName",
             "jurisdiction Of Incorporation CountryName");

  /* Logo Type definition, see http://www.ietf.org/rfc/rfc3709 */
  OBJ_create("1.3.6.1.5.5.7.1.12",
             "id-pe-logotype",
             "id-pe-logotype");
}

/* ---------------------------------------------------------- *
 * display_csr() shows CSR details in a HTML table.           *
 * ---------------------------------------------------------- */
void display_csr(X509_REQ *csr) {  
  int i = 0;
  char buf[81] = "";
  BIO *bio;
  bio = BIO_new(BIO_s_file());
  bio = BIO_new_fp(cgiOut, BIO_NOCLOSE);

  fprintf(cgiOut, "<table>");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "Certificate Signing Request Information");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>\n");

  /* Display the CN data */
  X509_NAME *reqname;
  X509_NAME_ENTRY *e;
  if (!(reqname = X509_REQ_get_subject_name(csr)))
    int_error("Unable to get the subject name from the request");

  for (i = 0; i < X509_NAME_entry_count(reqname); i++) {
    e = X509_NAME_get_entry(reqname, i);
    OBJ_obj2txt(buf, 80, e->object, 0);

    fprintf(cgiOut, "<tr>");
    fprintf(cgiOut, "<th class=\"cnt75\">%s</th\n>", buf);
    fprintf(cgiOut, "<td>");
    ASN1_STRING_print_ex(bio, e->value, ASN1_STRFLGS_UTF8_CONVERT);
    fprintf(cgiOut, "</td>");
    fprintf(cgiOut, "</tr>\n");
  }

  /* Display extensions, if included */
  STACK_OF(X509_EXTENSION) *ext_list = NULL;
  if ((ext_list = X509_REQ_get_extensions(csr)) != NULL) {
    fprintf(cgiOut, "<tr>");
    fprintf(cgiOut, "<th class=\"cnt\">Extensions:</th>\n");
    if (sk_X509_EXTENSION_num(ext_list) <= 0)
      fprintf(cgiOut, "<td>No extensions available");
    else {
      fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
      fprintf(cgiOut, "%d Extensions\n", sk_X509_EXTENSION_num(ext_list));
      fprintf(cgiOut, "<a href=\"javascript:elementHideShow('csrext');\">\n");
      fprintf(cgiOut, "Expand or Hide Extension Details</a>");
      /* display the cert extension list here */
      fprintf(cgiOut, "<div class=\"showext\" id=\"csrext\" style=\"display: none;\"><pre>");
      /* cycle through the cert extension list */
      for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ext;

        ext = sk_X509_EXTENSION_value(ext_list, i);
        obj = X509_EXTENSION_get_object(ext);

        fprintf(cgiOut, "Object %.2d: ", i);
        i2a_ASN1_OBJECT(bio, obj);
        fprintf(cgiOut, "\n");

        if (!X509V3_EXT_print(bio, ext, 0, 2)) {
          /* Some extensions (i.e. LogoType) have no handling    *
           * defined, we need to print their content as hex data */
          fprintf(cgiOut, "%*s", 2, "");
          M_ASN1_OCTET_STRING_print(bio, ext->value);
        }
        fprintf(cgiOut, "\n");

        if (i<sk_X509_EXTENSION_num(ext_list)-1)
        fprintf(cgiOut, "\n");
      }
      fprintf(cgiOut, "</pre></div>\n");
    }  
    fprintf(cgiOut, "</td>");
    fprintf(cgiOut, "</tr>\n");
  }

  /* display the key type and size here */
  EVP_PKEY *pkey  = NULL;
  if (! (pkey = X509_REQ_get_pubkey(csr)))
     int_error("Error getting public key from X509_REQ structure.");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th class=\"cnt\">Public Key:</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  if (pkey) {
    EC_KEY *myecc = NULL;
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(cgiOut, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(cgiOut, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_EC:
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        fprintf(cgiOut, "%d bit ECC Key, type %s", EVP_PKEY_bits(pkey),
                            OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
        break;
      default:
        fprintf(cgiOut, "%d bit %s Key", EVP_PKEY_bits(pkey), OBJ_nid2sn(pkey->type));
        break;
    }
  }

  fprintf(cgiOut, " <a href=\"javascript:elementHideShow('pubkey');\">\n");
  fprintf(cgiOut, "Expand or Hide Public Key Data</a>");
  /* display the public key data in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"pubkey\" style=\"display: none\"><pre>");
  if(!PEM_write_bio_PUBKEY(bio, pkey))
    BIO_printf(bio, "Error writing public key data in PEM format");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* ---------------------------------------------------------- *
   * Extract the CSR signature data.                            *
   * ---------------------------------------------------------- */
  ASN1_STRING     *asn1_sig = NULL;
  X509_ALGOR      *sig_type = NULL;
  size_t          sig_bytes = 0;
  char   sig_type_str[1024] = "";
  sig_type = csr->sig_alg;
  asn1_sig = csr->signature;
  sig_bytes = asn1_sig->length;
  OBJ_obj2txt(sig_type_str, sizeof(sig_type_str), sig_type->algorithm, 0);

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">Signature:</th>\n");
  if (strstr(sig_type_str, "Md5") || strstr(sig_type_str, "md5"))
    fprintf(cgiOut, "<td bgcolor=\"#cf0f0f\">");
  else fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "%s, Length: %d Bytes\n", sig_type_str, (int) sig_bytes);
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqsig');\">\n");
  fprintf(cgiOut, "Expand or Hide Signature Data</a>");
  /* display the signature in hex byte format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"reqsig\"  style=\"display: none\"><pre>");
  if (X509_signature_dump(bio, asn1_sig, 0) != 1)
    BIO_printf(bio, "Error printing the signature data\n");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* display the CSR in PEM format */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">CSR Data:</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqpem');\">\n");
  fprintf(cgiOut, "Expand/Hide Request data in PEM format</a>");
  fprintf(cgiOut, "<div class=\"showpem\" id=\"reqpem\"  style=\"display: none\">");
  fprintf(cgiOut, "<pre>\n");
  PEM_write_bio_X509_REQ(bio, csr);
  fprintf(cgiOut, "</pre>\n");
  fprintf(cgiOut, "</div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* display the CSR in TEXT format */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">CSR Text:</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">\n");
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqtext');\">\n");
  fprintf(cgiOut, "Expand/Hide Request data in Text format</a>\n");
  fprintf(cgiOut, "<div class=\"showtxt\" id=\"reqtext\" style=\"display: none\">\n");
  fprintf(cgiOut, "<pre>\n");
  if (! (X509_REQ_print_ex(bio, csr, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB), X509_FLAG_COMPAT)))
     int_error("Error printing certificate request text information");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">&nbsp;");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "</table>\n");
  BIO_free(bio);
}

/* ---------------------------------------------------------- *
 * display_key() shows key details in a HTML table.           *
 * ---------------------------------------------------------- */
void display_key(EVP_PKEY *pkey) {
  BIO *bio;
  bio = BIO_new(BIO_s_file());
  bio = BIO_new_fp(cgiOut, BIO_NOCLOSE);
  int id = 345563;

  fprintf(cgiOut, "<table>\n");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "Key Information");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th class=\"cnt75\">Private Key:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  /* display the key type and size here */
  if (pkey) {
    EC_KEY *myecc = NULL;
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(cgiOut, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(cgiOut, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_EC:
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        fprintf(cgiOut, "%d bit ECC Key, type %s", EVP_PKEY_bits(pkey),
                            OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
        break;
      default:
        fprintf(cgiOut, "%d bit non-RSA/DSA Key", EVP_PKEY_bits(pkey));
        break;
    }
  }

  fprintf(cgiOut, " <a href=\"javascript:elementHideShow('key_%d');\">\n", id+1);
  fprintf(cgiOut, "Expand or Hide Private Key Data</a>\n");
  /* display the public key data in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"key_%d\" style=\"display: none\">\n", id+1);
  fprintf(cgiOut, "<pre>");

  if(!PEM_write_bio_PrivateKey(bio, pkey,NULL,NULL,0,0,NULL))
    BIO_printf(bio, "Error writing private key data in PEM format");

  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Public Key:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  /* display the key type and size here */
  if (pkey) {
    EC_KEY *myecc = NULL;
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(cgiOut, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(cgiOut, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_EC:
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        fprintf(cgiOut, "%d bit ECC Key, type %s", EVP_PKEY_bits(pkey),
                            OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
        break;
      default:
        fprintf(cgiOut, "%d bit non-RSA/DSA Key", EVP_PKEY_bits(pkey));
        break;
    }
  }

  fprintf(cgiOut, " <a href=\"javascript:elementHideShow('key_%d');\">\n", id);
  fprintf(cgiOut, "Expand or Hide Public Key Data</a>\n");
  /* display the public key data in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"key_%d\" style=\"display: none\">\n", id);
  fprintf(cgiOut, "<pre>");

  if(!PEM_write_bio_PUBKEY(bio, pkey))
    BIO_printf(bio, "Error writing public key data in PEM format");

  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "&nbsp;</th>\n");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");
  BIO_free(bio);
}

/* ---------------------------------------------------------- *
 * display_cert() shows certificate details in a HTML table.  *
 * --> *ct is the certificate to display                      *
 * --> ct_type[] is the type (Root, Intermediate, Server...)  *
 * --> chain_type[] together with int level creates a unique  *
 * identifier for use with the Javascript Show/Hide function  *
 * ---------------------------------------------------------- */
void display_cert(X509 *ct, char ct_type[], char chain_type[], int level) {
  X509_NAME       *certname = NULL;
  X509_NAME     *issuername = NULL;
  X509_CINF       *cert_inf = NULL;
  STACK_OF(X509_EXTENSION) *ext_list;
  const EVP_MD *fprint_type = NULL;
  unsigned char fprint[EVP_MAX_MD_SIZE];
  ASN1_INTEGER *asn1_serial = 0;
             EVP_PKEY *pkey = NULL;
  unsigned int   thumb_size = 0;
  ASN1_STRING     *asn1_sig = NULL;
  X509_ALGOR      *sig_type = NULL;
  size_t          sig_bytes = 0;
  char   sig_type_str[1024] = "";
  long cert_version;
  int i;

  BIO *bio = BIO_new(BIO_s_file());
  bio = BIO_new_fp(cgiOut, BIO_NOCLOSE);
  /* ---------------------------------------------------------- *
   * extract and print various certificate information          *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(ct);

  issuername = X509_NAME_new();
  issuername = X509_get_issuer_name(ct);

  asn1_serial = X509_get_serialNumber(ct);

  cert_version = (X509_get_version(ct)+1);

  pkey = X509_get_pubkey(ct);

  fprint_type = EVP_sha256();
  if (!X509_digest(ct, fprint_type, fprint, &thumb_size))
    int_error("Error creating the certificate fingerprint.");

  /* ---------------------------------------------------------- *
   * Extract the certificate's extensions                       *
   * ---------------------------------------------------------- */
  cert_inf = ct->cert_info;
  ext_list = cert_inf->extensions;

  /* ---------------------------------------------------------- *
   * Extract the certificate's signature data.                  *
   * ---------------------------------------------------------- */
  sig_type = ct->sig_alg;
  asn1_sig = ct->signature;
  sig_bytes = asn1_sig->length;
  OBJ_obj2txt(sig_type_str, sizeof(sig_type_str), sig_type->algorithm, 0);

  fprintf(cgiOut, "<table>\n");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "%s Certificate Information", ct_type);
  if (level >= 0) fprintf(cgiOut, " %d", level+1);
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th class=\"cnt75\">Version:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert subject here */
  fprintf(cgiOut, "%ld", cert_version);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Subject:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert subject here */
  X509_NAME_print_ex_fp(cgiOut, certname, 0,
         ASN1_STRFLGS_UTF8_CONVERT|XN_FLAG_SEP_CPLUS_SPC);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Serial:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert serial here */
  i2a_ASN1_INTEGER(bio, asn1_serial);
  BIO_puts(bio,"\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Issuer:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert issuer here */
  X509_NAME_print_ex_fp(cgiOut, issuername, 0, 0);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Thumbprint:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the thumbprint here */
  BIO_printf(bio, "%s", OBJ_nid2sn(EVP_MD_type(fprint_type)));
  BIO_printf(bio,": ");
  for (i=0; i<thumb_size; ++i) BIO_printf(bio, "%02x ", fprint[i]);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Validity:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the start and end date here */
  fprintf(cgiOut, "Start Date: ");
  if (!ASN1_TIME_print(bio ,X509_get_notBefore(ct)))
    fprintf(cgiOut, "***n/a***");
  fprintf(cgiOut, " &nbsp; End Date: ");
  if (!ASN1_TIME_print(bio ,X509_get_notAfter(ct)))
    fprintf(cgiOut, "***n/a***");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Extensions:");
  fprintf(cgiOut, "</th>\n");
  if (sk_X509_EXTENSION_num(ext_list) <= 0)
    fprintf(cgiOut, "<td>No extensions available");
  else {
    fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
    fprintf(cgiOut, "%d Extensions\n", sk_X509_EXTENSION_num(ext_list));
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certext_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Extension Details</a>");
  /* display the cert extension list here */
  fprintf(cgiOut, "<div class=\"showext\" id=\"certext_%s%d\" style=\"display: none;\"><pre>", chain_type, level);
  for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext;

    ext = sk_X509_EXTENSION_value(ext_list, i);

    obj = X509_EXTENSION_get_object(ext);
    fprintf(cgiOut, "Object %.2d: ", i);
    i2a_ASN1_OBJECT(bio, obj);
    fprintf(cgiOut, "\n");

    if (!X509V3_EXT_print(bio, ext, 0, 2)) {
    /* Some extensions (i.e. LogoType) have no handling    *
     * defined, we need to print their content as hex data */
      fprintf(cgiOut, "%*s", 2, "");
      M_ASN1_OCTET_STRING_print(bio, ext->value);
    }
    fprintf(cgiOut, "\n");

    if (i<sk_X509_EXTENSION_num(ext_list)-1)
      fprintf(cgiOut, "\n");
  }

  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  }
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Public Key:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  /* display the key type and size here */
  if (pkey) {
    EC_KEY *myecc = NULL;
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(cgiOut, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(cgiOut, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_EC:
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        fprintf(cgiOut, "%d bit ECC Key, type %s", EVP_PKEY_bits(pkey),
                            OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
        break;
      default:
        fprintf(cgiOut, "%d bit non-RSA/DSA Key", EVP_PKEY_bits(pkey));
        break;
    }
  }

  fprintf(cgiOut, " <a href=\"javascript:elementHideShow('pubkey_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Public Key Data</a>\n");
  /* display the public key data in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"pubkey_%s%d\" style=\"display: none\">\n", chain_type, level);
  fprintf(cgiOut, "<pre>");
  if(!PEM_write_bio_PUBKEY(bio, pkey))
    BIO_printf(bio, "Error writing public key data in PEM format");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Signature:");
  fprintf(cgiOut, "</th>\n");
  if (strstr(sig_type_str, "Md5") || strstr(sig_type_str, "md5"))
    fprintf(cgiOut, "<td bgcolor=\"#cf0f0f\">");
  else fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "%s, Length: %d Bytes\n", sig_type_str, (int) sig_bytes);
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certsig_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Signature Data</a>\n");
  /* display the cert signature in hex byte format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"certsig_%s%d\" style=\"display: none\">\n", chain_type, level);
  fprintf(cgiOut, "<pre>");
  if (X509_signature_dump(bio, asn1_sig, 0) != 1)
    BIO_printf(bio, "Error printing the signature data\n"); 
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* display the cert content in PEM format here */
  BIO *test = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(test, ct);
  long PEM_size = BIO_get_mem_data(test, NULL);
  BIO_free(test);
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Cert Data:</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "Length: %ld Bytes ", PEM_size);
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certpem_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Certificate PEM Data</a>\n");
  fprintf(cgiOut, "<div class=\"showpem\" id=\"certpem_%s%d\" style=\"display: none\">\n",chain_type, level);
  fprintf(cgiOut, "<pre>");
  PEM_write_bio_X509(bio, ct);
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* display the cert content in TEXT format here */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Cert Text:</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">\n");
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certtext_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand/Hide certificate data in Text format</a>\n");
  fprintf(cgiOut, "<div class=\"showtxt\" id=\"certtext_%s%d\" style=\"display: none\">\n", chain_type, level);
  fprintf(cgiOut, "<pre>\n");
  if (! (X509_print_ex_fp(cgiOut, ct, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB), X509_FLAG_COMPAT)))
     int_error("Error printing certificate text information");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">&nbsp;");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "</table>\n");
  BIO_free(bio);
}
/* ---------------------------------------------------------- *
 * display_crl() shows CRL details in a HTML table.           *
 * ---------------------------------------------------------- */
void display_crl(X509_CRL *crl) {
  BIO *bio;
  bio = BIO_new(BIO_s_file());
  bio = BIO_new_fp(cgiOut, BIO_NOCLOSE);

  fprintf(cgiOut, "<table>");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "Certificate Revocation List Information");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>\n");

  // location
  const char *crluri = CRLURI;
  crluri = crluri+4; // move the pointer past "URI:"
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Location:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td><a href=\"%s\">%s</a>\n", crluri, crluri);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  // size
  struct stat fstat;
  unsigned long crl_fsize = 0;
  if (stat(CRLPATH, &fstat) == 0) crl_fsize = fstat.st_size;
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">File Size:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>%lu Bytes\n", crl_fsize);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  // version
  long version = 0;
  version = X509_CRL_get_version(crl);
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Version:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>%lu (0x%lx)\n", version+1, version);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");


  // issuer
  X509_NAME *issuer = NULL;
  issuer = X509_NAME_new();
  issuer = X509_CRL_get_issuer(crl);

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Issuer:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>\n");
  X509_NAME_print_ex(bio, issuer, 0, XN_FLAG_ONELINE);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  // lastupdate
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Last Update:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>\n");
  if (!ASN1_TIME_print(bio, X509_CRL_get_lastUpdate(crl)))
    fprintf(cgiOut, "***n/a***");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  // nextupdate
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Next Update:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>\n");
  if (!ASN1_TIME_print(bio, X509_CRL_get_nextUpdate(crl)))
    fprintf(cgiOut, "***n/a***");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  // extensions (if included)
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th class=\"cnt\">Extensions:</th>\n");

  int extnum = 0;
  extnum = X509_CRL_get_ext_count(crl);
  if (extnum <= 0) {
    fprintf(cgiOut, "<td>No extensions available");
  }
  else {
    // If we got extensions (only v2 CRLs)
    fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
    fprintf(cgiOut, "%d Extensions\n", extnum);
    fprintf(cgiOut, "<a href=\"javascript:elementHideShow('csrext');\">\n");
    fprintf(cgiOut, "Expand or Hide Extension Details</a>");
    fprintf(cgiOut, "<div class=\"showext\" id=\"csrext\" style=\"display: none;\"><pre>");
    /* cycle through the extension list */
    int i;
    for (i=0; i<extnum; i++) {
      ASN1_OBJECT *obj;
      X509_EXTENSION *ext;

      ext = X509_CRL_get_ext(crl, i);
      obj = X509_EXTENSION_get_object(ext);

      fprintf(cgiOut, "Object %.2d: ", i);
      i2a_ASN1_OBJECT(bio, obj);
      fprintf(cgiOut, "\n");

      if (!X509V3_EXT_print(bio, ext, 0, 2)) {
        /* Some extensions (i.e. LogoType) have no handling    *
         * defined, we need to print their content as hex data */
        fprintf(cgiOut, "%*s", 2, "");
        M_ASN1_OCTET_STRING_print(bio, ext->value);
      }
      fprintf(cgiOut, "\n");

      if (i<(extnum-1)) fprintf(cgiOut, "\n");
    }
    fprintf(cgiOut, "</pre></div>\n");
  }
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "</tr>\n");

  //signature
  ASN1_STRING     *asn1_sig = NULL;
  X509_ALGOR      *sig_type = NULL;
  size_t          sig_bytes = 0;
  char   sig_type_str[1024] = "";
  sig_type = crl->sig_alg;
  asn1_sig = crl->signature;
  sig_bytes = asn1_sig->length;
  OBJ_obj2txt(sig_type_str, sizeof(sig_type_str), sig_type->algorithm, 0);

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\">Signature:</th>\n");
  if (strstr(sig_type_str, "Md5") || strstr(sig_type_str, "md5"))
    fprintf(cgiOut, "<td bgcolor=\"#cf0f0f\">");
  else fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");

  fprintf(cgiOut, "%s, Length: %d Bytes\n", sig_type_str, (int) sig_bytes);
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqsig');\">\n");
  fprintf(cgiOut, "Expand or Hide Signature Data</a>");
  /* display the signature in hex byte format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"reqsig\"  style=\"display: none\"><pre>");
  if (X509_signature_dump(bio, asn1_sig, 0) != 1)
    BIO_printf(bio, "Error printing the signature data\n");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  // number of revoked certs
  STACK_OF(X509_REVOKED) *rev = X509_CRL_get_REVOKED(crl);
  int revnum = sk_X509_REVOKED_num(rev);

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt75\"># Revoked Certs:");
  fprintf(cgiOut, "</th>\n");
  if (revnum < 1) fprintf(cgiOut, "<td>None\n");
  else fprintf(cgiOut, "<td>%d\n", revnum);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">&nbsp;");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "</table>\n");
  BIO_free(bio);
}

/* ---------------------------------------------------------- *
 * X509_load_ca_file() loads a CA file into a mem BIO using   *
 * (BIO_read_filename(), PEM_X509_INFO_read_bio() puts them   *
 * in a stack, which is then to be added to a store or CTX.   *
 * ---------------------------------------------------------- */
STACK_OF(X509_INFO) *X509_load_ca_file(int *cert_count,
                      struct stat *fstat, const char *file) {
  STACK_OF(X509_INFO) *st = NULL;
  BIO *inbio=NULL;

  /* ---------------------------------------------------------- *
   * complain if we got an empty filename                       *
   * ---------------------------------------------------------- */
  if (file == NULL)
    int_error("Error receiving a valid CA bundle file name.\n");

  /* ---------------------------------------------------------- *
   * get file status data                                       *
   * ---------------------------------------------------------- */
  if (stat(file, fstat) != 0)
    int_error("Error cannot stat CA cert bundle file.\n");

  /* ---------------------------------------------------------- *
   * complain if the file is empty (0 bytes)                    *
   * ---------------------------------------------------------- */
  if(fstat->st_size == 0)
    int_error("Error CA cert bundle file size is zero bytes.\n");

  inbio=BIO_new(BIO_s_file_internal());

  /* ---------------------------------------------------------- *
   * check if we can open the file for reading                  *
   * ---------------------------------------------------------- */
  if ((inbio == NULL) || (BIO_read_filename(inbio, file) <= 0))
    int_error("Error loading CA cert bundle file into memory.\n");

  /* ---------------------------------------------------------- *
   * read all certificates from file                            *
   * ---------------------------------------------------------- */
  if (! (st = PEM_X509_INFO_read_bio(inbio, NULL, NULL, NULL)))
    int_error("Error reading CA certs from BIO.\n");

  /* ---------------------------------------------------------- *
   * get the number of certs that are now on the stack          *
   * ---------------------------------------------------------- */
  *cert_count = sk_X509_INFO_num(st);

  /* ---------------------------------------------------------- *
   * return the STACK_OF(X509_INFO) pointer, or NULL            *
   * ---------------------------------------------------------- */
  if (cert_count > 0) return st;
  else return NULL;
}

void display_signing(X509_REQ *csr) {
  char startdate[11]    ="";
  char enddate[11]      ="";
  char starttime[9]     ="";
  char endtime[9]       ="";

/* ------------------------------------------------------------------------ *
 * Calculate default date and time strings                                  *
 * ------------------------------------------------------------------------ */
   time_t now = time(NULL);
   struct tm *tm = gmtime(&now);

   if (tm == NULL) {
     strncpy(startdate, "YYYY-MM-DD", sizeof(startdate));
     strncpy(starttime, "HH:MM:SS", sizeof(starttime));
   }
   else {
     strftime(startdate, sizeof(startdate), "%Y-%m-%d", tm);
     strftime(starttime, sizeof(starttime), "%H:%M:%S", tm);
   }

   now = now + (time_t) (DAYS_VALID*60*60*24);
   tm = gmtime(&now);

   if (tm == NULL) {
     strncpy(enddate, "YYYY-MM-DD", sizeof(enddate));
     strncpy(endtime, "HH:MM:SS", sizeof(endtime));
   }
   else {
     strftime(enddate, sizeof(enddate), "%Y-%m-%d", tm);
     strftime(endtime, sizeof(endtime), "%H:%M:%S", tm);
   }

  BIO *bio;
  bio = BIO_new(BIO_s_file());
  bio = BIO_new_fp(cgiOut, BIO_NOCLOSE);

  fprintf(cgiOut, "<form action=\"certsign.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"csrdata\" ");
  fprintf(cgiOut, "value=\"");
  PEM_write_bio_X509_REQ(bio, csr);
  fprintf(cgiOut, "\">\n");

  /* Add extra extensions, define validity */
  fprintf(cgiOut, "<table>");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"3\">");
  fprintf(cgiOut, "Define certificate attributes:");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>\n");

  /* Add Key Usage */
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th class=\"cnt\">");
  fprintf(cgiOut, "<input type=\"checkbox\" name=\"keyusage\" checked id=\"key_cb\" onclick=\"switchGrey('key_cb', 'key_td', 'none', 'none');\" />");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<td class=type>");
  fprintf(cgiOut, "Key Usage:</td>");
  fprintf(cgiOut, "<td id=\"key_td\" style=\"padding: 0;\">");
  fprintf(cgiOut, "<table style=\"border-style: none;\"><tr><td>");
  fprintf(cgiOut, "<input type=radio name=\"type\" value=sv checked>");
  fprintf(cgiOut, " SSL Server</td></tr><tr>");
  fprintf(cgiOut, "<td>");
  fprintf(cgiOut, "<input type=radio name=\"type\" value=cl>");
  fprintf(cgiOut, " SSL Client</td></tr><tr>\n");
  fprintf(cgiOut, "<td>");
  fprintf(cgiOut, "<input type=radio name=\"type\" value=em>");
  fprintf(cgiOut, " E-Mail Encryption ");
  fprintf(cgiOut, "<input type=text size=20 name=\"ename\">");
  fprintf(cgiOut, " Address</td></tr><tr>");
  fprintf(cgiOut, "<td>");
  fprintf(cgiOut, "<input type=radio name=\"type\" value=os>");
  fprintf(cgiOut, " Object Signing</td></tr><tr>\n");
  fprintf(cgiOut, "<td>");
  fprintf(cgiOut, "<input type=radio name=\"type\" value=ca>");
  fprintf(cgiOut, " CA Certificate</td></tr>");
  fprintf(cgiOut, "</td></tr></table></td></tr>\n");

  /* Add extended key usage */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">");
  fprintf(cgiOut, "<input type=\"checkbox\" name=\"extkeyusage\" id=\"exkey_cb\" onclick=\"switchGrey('exkey_cb', 'exkey_td', 'none', 'none');\" />");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<td class=\"type\">");
  fprintf(cgiOut, "Extended Key Usage:");
  fprintf(cgiOut, "</td>\n");

  fprintf(cgiOut, "<td class=\"type\" id=\"exkey_td\">\n");
  fprintf(cgiOut, "<select name=\"extkeytype\">");
  fprintf(cgiOut, "<option value=\"tlsws\" selected=\"selected\">");
  fprintf(cgiOut, "TLS Web server authentication</option>");
  fprintf(cgiOut, "<option value=\"tlscl\">TLS Web client authentication</option>");
  fprintf(cgiOut, "<option value=\"cs\">Code Signing</option>");
  fprintf(cgiOut, "<option value=\"ep\">Email Protection</option>");
  fprintf(cgiOut, "<option value=\"ts\">Time Stamping</option>");
  fprintf(cgiOut, "<option value=\"ocsp\">OCSP Signing</option>");
  fprintf(cgiOut, "</select>");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* Add crlDistributionPoints */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">");
  fprintf(cgiOut, "<input type=\"checkbox\" name=\"addcrluri\" id=\"crluri_cb\" onclick=\"switchGrey('crluri_cb', 'crluri_td', 'none', 'none');\" />");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<td class=\"type\">");
  fprintf(cgiOut, "crlDistributionPoints:");
  fprintf(cgiOut, "</td>\n");

  fprintf(cgiOut, "<td class=\"even\" id=\"crluri_td\">\n");
  fprintf(cgiOut, CRLURI);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* Set validity from now */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">");
  fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"days_cb\" value=vd checked onclick=\"switchGrey('days_cb', 'days_td', 'date_td', 'none');\" />");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<td class=type>");
  fprintf(cgiOut, "Set Validity (in Days):");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "<td id=\"days_td\">");
  fprintf(cgiOut, " From now until <input type=text name=\"daysvalid\" size=4 value=%d> Days", DAYS_VALID);
  fprintf(cgiOut, "<br />");
  fprintf(cgiOut, "365 = 1 year, 730 = 2 years, 1095 = 3 years, 1460 = 4 years, 1825 = 5 years");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  /* Set validity by date */
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th class=\"cnt\">");
  fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"date_cb\" value=se onclick=\"switchGrey('date_cb', 'date_td', 'days_td', 'none')\" />");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<td class=\"type\">");
  fprintf(cgiOut, "Set Validity (by Date):");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "<td class=\"type\" id=\"date_td\">");
  fprintf(cgiOut, "<input type=text name=\"startdate\" size=15 value=%s>", startdate);
  fprintf(cgiOut, " Start Date ");
  fprintf(cgiOut, "<input type=text name=\"starttime\" size=10 value=%s>", starttime);
  fprintf(cgiOut, " Start Time (UTC)");
  fprintf(cgiOut, "<br />");
  fprintf(cgiOut, "<input type=text name=\"enddate\" size=15 value=%s>", enddate);
  fprintf(cgiOut, " End Date &nbsp;");
  fprintf(cgiOut, "<input type=text name=\"endtime\" size=10 value=%s>", endtime);
  fprintf(cgiOut, " End Time (UTC)");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th class=\"cnt\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td class=\"type\">CA Signing Algorithm:</td>\n");

  fprintf(cgiOut, "<td id=\"sigalg\">");
  fprintf(cgiOut, "<select name=\"sigalg\">\n");
  fprintf(cgiOut, "<option value=\"SHA-224\">Strength: SHA-224 bit (Fair)</option>\n");
  fprintf(cgiOut, "<option value=\"SHA-256\" selected=\"selected\">Strength: SHA-256 bit (Good)</option>\n");
  fprintf(cgiOut, "<option value=\"SHA-384\">Strength: SHA-384 bit (Better)</option>\n");
  fprintf(cgiOut, "<option value=\"SHA-512\">Strength: SHA-512 bit (Best)");
  fprintf(cgiOut, "</option>\n</select>");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");


  fprintf(cgiOut, "<tr><th colspan=\"3\">");
  fprintf(cgiOut, "<input type=\"button\" name=\"Forget it!\" value=");
  fprintf(cgiOut, "\"  Go Back  \" onclick=");
  fprintf(cgiOut, "\"self.location.href='certrequest.cgi'\">&nbsp;");
  fprintf(cgiOut, "&nbsp;<input type=\"button\" value=\"Print Page\" ");
  fprintf(cgiOut, "onclick=\"print(); return false;\">&nbsp;");
  fprintf(cgiOut, "&nbsp;<input type=\"submit\" value=\"Sign Request\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");
  fprintf(cgiOut, "</form>\n");
  BIO_free(bio);
}

/* ---------------------------------------------------------- *
 * keycreate_input() provides a HMTL table selcting a new key *
 * ---------------------------------------------------------- */
void keycreate_input() {
   fprintf(cgiOut, "<table>");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">Create a New Certificate Key - Choose Key Type and Strength:</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">");
   fprintf(cgiOut, "<input type=\"radio\" id=\"rsa_rb\" checked=\"checked\" name=\"keytype\" value=\"rsa\" onclick=\"switchGrey('rsa_rb', 'rsa', 'dsa', 'ecc');\" /></th>\n");
   fprintf(cgiOut, "<td class=\"type130\">Generate RSA key pair</td>\n");
   fprintf(cgiOut, "<td id=\"rsa\">");
   fprintf(cgiOut, "<select name=\"rsastrength\">\n");
   fprintf(cgiOut, "<option value=\"512\">Key Strength: 512 bit (Poor)</option>\n");
   fprintf(cgiOut, "<option value=\"1024\">Key Strength: 1024 bit (Fair)</option>\n");
   fprintf(cgiOut, "<option value=\"2048\" selected=\"selected\">Key Strength: 2048 bit (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"4096\">Key Strength: 4096 bit (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td class=\"desc180\">select RSA key size here</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">");
   fprintf(cgiOut, "<input type=\"radio\" id=\"dsa_rb\" name=\"keytype\" value=\"dsa\" onclick=\"switchGrey('dsa_rb', 'dsa', 'rsa', 'ecc');\" /></th>\n");
   fprintf(cgiOut, "<td class=\"type130\">Generate DSA key pair</td>\n");
   fprintf(cgiOut, "<td class=\"type\" id=\"dsa\">");
   fprintf(cgiOut, "<select name=\"dsastrength\">\n");
   fprintf(cgiOut, "<option value=\"512\">Key Strength: 512 bit (Poor)</option>\n");
   fprintf(cgiOut, "<option value=\"1024\">Key Strength: 1024 bit (Fair)</option>\n");
   fprintf(cgiOut, "<option value=\"2048\" selected=\"selected\">Key Strength: 2048 bit (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"4096\">Key Strength: 4096 bit (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td class=\"desc180\">select DSA key size here</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">");
   fprintf(cgiOut, "<input type=\"radio\" id=\"ecc_rb\" name=\"keytype\" value=\"ecc\" onclick=\"switchGrey('ecc_rb', 'ecc', 'rsa', 'dsa');\" /></th>\n");
   fprintf(cgiOut, "<td class=\"type130\">Generate ECC key pair</td>\n");
   fprintf(cgiOut, "<td class=\"type\" id=\"ecc\">");
   fprintf(cgiOut, "<select name=\"eccstrength\">\n");
   fprintf(cgiOut, "<option value=\"secp224r1\">Key Type: secp224r1 (OK)</option>\n");
   fprintf(cgiOut, "<option value=\"secp256k1\" selected=\"selected\">Key Type: secp256k1 (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"secp384r1\">Key Type: secp384r1 (Better)</option>\n");
   fprintf(cgiOut, "<option value=\"secp521r1\">Key Type: secp521r1 (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td class=\"desc180\">select ECC key size here</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">Select CSR Signature Algorithm:</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "<td class=\"type\">CSR Signing Algorithm:</td>\n");
   fprintf(cgiOut, "<td id=\"sigalg\">");
   fprintf(cgiOut, "<select name=\"sigalg\">\n");
   fprintf(cgiOut, "<option value=\"SHA-224\">Strength: SHA-224 bit (Fair)</option>\n");
   fprintf(cgiOut, "<option value=\"SHA-256\" selected=\"selected\">Strength: SHA-256 bit (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"SHA-384\">Strength: SHA-384 bit (Better)</option>\n");
   fprintf(cgiOut, "<option value=\"SHA-512\">Strength: SHA-512 bit (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td class=\"desc180\">select CSR signing algorithm here</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr><th colspan=\"4\">&nbsp</th></tr>\n");
   fprintf(cgiOut, "</table>\n");
}

/* ------------------------------------------------------------- *
 * Function cgi_load_csrfile() loads a CGI form called "csrfile" *
 * into a X509_REQ struct.                                       *
 * ------------------------------------------------------------- */
X509_REQ * cgi_load_csrfile(char *file) {
X509_REQ *csr = NULL;
  /* ---------------------------------------------------------- *
   * Get the certificate request file size                      *
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
  * check if a CSR contains PEM data                           *
  * ---------------------------------------------------------- */
  csr_validate_PEM(csr_form);

 /* ---------------------------------------------------------- *
  * Try to read the PEM request with openssl lib functions     *
  * ---------------------------------------------------------- */
  BIO *csrbio = BIO_new_mem_buf(csr_form, -1);

  if (! (csr = PEM_read_bio_X509_REQ(csrbio, NULL, 0, NULL))) {
    snprintf(error_str, sizeof(error_str), "Error reading csr structure of %s into memory", file);
    int_error(error_str);
  }
  BIO_free(csrbio);
  return csr;
}
/* ------------------------------------------------------------- *
 * Function cgi_load_csrform() loads a CGI form called "csrdata" * 
 * into a X509_REQ struct.                                       *
 * ------------------------------------------------------------- */
X509_REQ * cgi_load_csrform(char *csr_form) {
X509_REQ *csr = NULL;

 /* ---------------------------------------------------------- *
  * check if a CSR was pasted or if someone just sends garbage *
  * ---------------------------------------------------------- */
  csr_validate_PEM(csr_form);

 /* ---------------------------------------------------------- *
  * Try to read the PEM request with openssl lib functions     *
  * ---------------------------------------------------------- */
  BIO *csrbio = BIO_new_mem_buf(csr_form, -1);

  if (! (csr = PEM_read_bio_X509_REQ(csrbio, NULL, 0, NULL)))
    int_error("Error reading PEM csr structure from form data");

  BIO_free(csrbio);
  return csr;
}

/* ------------------------------------------------------------ *
 * Function cgi_load_certfile() loads a CGI form named          *
 * "certfile" into a X509 struct.                               *
 * ------------------------------------------------------------ */
X509 * cgi_load_certfile(char* file) {
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
  BIO *certbio = BIO_new_mem_buf(cert_form, -1);

  if (! (crt = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    snprintf(error_str, sizeof(error_str), "Error reading cert structure of %s into memory", file);
    int_error(error_str);
  }

  BIO_free(certbio);
  return crt;
}

/* ------------------------------------------------------------- *
 * Function cgi_load_keyfile() loads a CGI form named "keyfile"  *
 * into a EVP_PKEY struct.                                       *
 * ------------------------------------------------------------- */
EVP_PKEY * cgi_load_keyfile(char* file) {
EVP_PKEY *key = NULL;
  /* ---------------------------------------------------------- *
   * Get the key file size                                      *
   * ---------------------------------------------------------- */
  int key_fsize = 0;

  cgiFormFileSize("keyfile", &key_fsize);
  if (key_fsize == 0) int_error("The uploaded key file is empty (0 bytes)");
  if (key_fsize > KEYLEN) {
    snprintf(error_str, sizeof(error_str), "The uploaded key file greater %d bytes", KEYLEN);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Open the key file and get a handle                         *
   * ---------------------------------------------------------- */
  cgiFilePtr keyfile_ptr = NULL;

  if (cgiFormFileOpen("keyfile", & keyfile_ptr) != cgiFormSuccess) {
    snprintf(error_str, sizeof(error_str), "Cannot open the uploaded key file %s", file);
    int_error(error_str);
  }

  /* ---------------------------------------------------------- *
   * Read the key file content in a buffer                      *
   * ---------------------------------------------------------- */
  char key_form[KEYLEN] = "";

  if (! (cgiFormFileRead(keyfile_ptr, key_form, KEYLEN, &key_fsize) == cgiFormSuccess)) {
    snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded key file %s", file);
    int_error(error_str);
  }

 /* ---------------------------------------------------------- *
  * check if a key contains PEM data                           *
  * ---------------------------------------------------------- */
  key_validate_PEM(key_form);

  /* ---------------------------------------------------------- *
   * Load the key data into the EVP_PKEY struct                 *
   * ---------------------------------------------------------- */
  BIO *keybio = BIO_new_mem_buf(key_form, -1);

  if (! (key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL))) {
    snprintf(error_str, sizeof(error_str), "Error reading private key structure of %s into memory", file);
    int_error(error_str);
  }

  BIO_free(keybio);
  return key;
}

/* ------------------------------------------------------------- *
 * Function cgi_load_crlfile() loads a OpenSSL generated CRL     *
 * file into a X509_CRL struct.                                  *
 * ------------------------------------------------------------- */
X509_CRL * cgi_load_crlfile(char *file) {
  X509_CRL *crl = NULL;
  BIO *in = NULL;
  /* ---------------------------------------------------------- *
   * complain if we got an empty filename                       *
   * ---------------------------------------------------------- */
  if (file == NULL)
    int_error("Error receiving a valid CRL file name.\n");

  /* ---------------------------------------------------------- *
   * get file status data                                       *
   * ---------------------------------------------------------- */
  struct stat fstat;
  if (stat(file, &fstat) != 0)
    int_error("Error cannot stat CRL file.\n");

  /* ---------------------------------------------------------- *
   * Get the crl file size, complain if file is empty (0 bytes) *
   * ---------------------------------------------------------- */
  int crl_fsize = fstat.st_size;

  if(crl_fsize == 0)
    int_error("Error CRL file size is zero bytes.\n");

  in=BIO_new(BIO_s_file_internal());

  /* ---------------------------------------------------------- *
   * check if we can open the file for reading                  *
   * ---------------------------------------------------------- */
  if ((in == NULL) || (BIO_read_filename(in, file) <= 0))
    int_error("Error loading CRL file into memory.\n");

  /* ---------------------------------------------------------- *
   * Try to read CRL from PEM file                              *
   * ---------------------------------------------------------- */
  if (! (crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL)))
    int_error("Error reading crl file to BIO.\n");

  BIO_free(in);
  return crl;
}
