/* -------------------------------------------------------------------------- *
 * file:         webcert.c                                                    *
 * purpose:      Shared functions across multiple CGI                         *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
  fprintf(cgiOut, "<th width=\"70px\">Private Key:");
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
  fprintf(cgiOut, "<th width=\"70px\">Public Key:");
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

  BIO *bio;
  bio = BIO_new(BIO_s_file());
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
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th width=\"70px\">Version:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert subject here */
  fprintf(cgiOut, "%ld", cert_version);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th width=\"70px\">Subject:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert subject here */
  X509_NAME_print_ex_fp(cgiOut, certname, 0,
         ASN1_STRFLGS_UTF8_CONVERT|XN_FLAG_SEP_CPLUS_SPC);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Serial:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert serial here */
  i2a_ASN1_INTEGER(bio, asn1_serial);
  BIO_puts(bio,"\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Issuer:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert issuer here */
  X509_NAME_print_ex_fp(cgiOut, issuername, 0, 0);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Thumbprint:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the thumbprint here */
  BIO_printf(bio, "%s", OBJ_nid2sn(EVP_MD_type(fprint_type)));
  BIO_printf(bio,": ");
  for (i=0; i<thumb_size; ++i) BIO_printf(bio, "%02x ", fprint[i]);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Validity:");
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
  fprintf(cgiOut, "<th>Extensions:");
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
  fprintf(cgiOut, "<th>Public Key:");
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
  fprintf(cgiOut, "<th>Signature:");
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

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Cert Data: ");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certpem_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Certificate PEM Data</a>\n");
  /* display the cert content in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"certpem_%s%d\" style=\"display: none\">\n",chain_type, level);
  fprintf(cgiOut, "<pre>");
  PEM_write_bio_X509(bio, ct);
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
