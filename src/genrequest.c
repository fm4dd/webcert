/* -------------------------------------------------------------------------- *
 * file:	genrequest.cgi                                                *
 * purpose:	takes the input from buildrequest.cgi. It generates and       *
 *              displays the CSR after creating a public/private key pair     *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "webcert.h"

/* ---------------------------------------------------------- *
 * This function attempts to get the DNS name from a given IP *
 * ---------------------------------------------------------- */
char * get_dns(char *ip) {
  struct hostent *host;
  struct in_addr *my_addr;

  my_addr=(struct in_addr*)malloc(sizeof(struct in_addr));
  my_addr->s_addr=inet_addr(ip);
  host = gethostbyaddr((char *) my_addr, 4, AF_INET);
  if(host != NULL) return host->h_name;
  else return "unknown";
}

int cgiMain() {
   X509_REQ 	*webrequest 	 = NULL;
   EVP_PKEY	*pkey		 = NULL;
   X509_NAME 	*reqname	 = NULL;
   DSA 		*mydsa		 = NULL;
   RSA 		*myrsa		 = NULL;
   EC_KEY       *myecc           = NULL;
   EVP_MD        const *digest   = NULL;

   BIO 		*outbio		 = NULL;
   STACK_OF(X509_EXTENSION) 
                       *ext_list = NULL;
   char         country[81]      = "";
   char         province[81]     = "";
   char         locality[81]     = "";
   char         organisation[81] = "";
   char         department[81]   = "";
   char 	email_addr[81]   = "";
   char 	cname[81]        = "";
   char 	typesan1[81]     = "";
   char 	typesan2[81]     = "";
   char 	typesan3[81]     = "";
   char 	typesan4[81]     = "";
   char         datasan1[255]    = "";
   char         datasan2[255]    = "";
   char         datasan3[255]    = "";
   char         datasan4[255]    = "";
   char 	surname[81]      = "";
   char 	givenname[81]    = "";

   char 	keytype[81]      = "";
   int	 	rsastrength	 = 0;
   int	 	dsastrength	 = 0;
   char	 	eccstrength[255] ="";
   char         sigalgstr[41]    = "SHA-256";

   static char 	title[] = "Generate the Certificate Request";

/* ------------------------------------------------------------------------- *
 * manage the parameter input and collect the certificate input data         *
 * --------------------------------------------------------------------------*/

   cgiFormString("c", country, sizeof(country));
   cgiFormString("st", province, sizeof(province));
   cgiFormString("l", locality, sizeof(locality));
   cgiFormString("o", organisation, sizeof(organisation));
   cgiFormString("ou", department, sizeof(department));
   cgiFormString("email", email_addr, sizeof(email_addr));
   cgiFormString("cn", cname, sizeof(cname));
   cgiFormString("typesan1", typesan1, sizeof(typesan1));
   cgiFormString("typesan2", typesan2, sizeof(typesan2));
   cgiFormString("typesan3", typesan3, sizeof(typesan3));
   cgiFormString("typesan4", typesan4, sizeof(typesan4));
   cgiFormString("datasan1", datasan1, sizeof(datasan1));
   cgiFormString("datasan2", datasan2, sizeof(datasan2));
   cgiFormString("datasan3", datasan3, sizeof(datasan3));
   cgiFormString("datasan4", datasan4, sizeof(datasan4));
   cgiFormString("sn", surname, sizeof(surname));
   cgiFormString("gn", givenname, sizeof(givenname));

   cgiFormString("keytype", keytype, sizeof(keytype));
   cgiFormInteger("rsastrength", &rsastrength, 0);
   cgiFormInteger("dsastrength", &dsastrength, 0);
   cgiFormString("eccstrength", eccstrength, sizeof(eccstrength));

/* we do not accept requests with no data, i.e. being empty with just a 
   public key. Although technically possible to sign and create a cert,
   they don't make much sense. We require here at least one CN supplied.    */

   if(strlen(cname) == 0)
     int_error("No CN has been provided. The CN field is mandatory.");

/* ------------------------------------------------------------------------ *
 * These function calls are essential to make many PEM + other openssl      *
 * functions work.                                                          *
 * ------------------------------------------------------------------------ */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
   ERR_load_BIO_strings();

/* ------------------------------------------------------------------------- *
 * Generate the key pair based on the selected keytype                       *
 * ------------------------------------------------------------------------- */
   if ((pkey=EVP_PKEY_new()) == NULL)
      int_error("Error creating EVP_PKEY structure.");

   if(strcmp(keytype, "rsa") == 0) {
      myrsa = RSA_new();
      if (! (myrsa = RSA_generate_key(rsastrength, RSA_F4, NULL, NULL)))
         int_error("Error generating the RSA key.");

      if (!EVP_PKEY_assign_RSA(pkey,myrsa))
         int_error("Error assigning RSA key to EVP_PKEY structure.");
    }

   else if(strcmp(keytype, "dsa") == 0) {
      mydsa = DSA_new();
      mydsa = DSA_generate_parameters(dsastrength, NULL, 0, NULL, NULL,
                                                            NULL, NULL);
      if (! (DSA_generate_key(mydsa)))
         int_error("Error generating the DSA key.");

      if (!EVP_PKEY_assign_DSA(pkey,mydsa))
         int_error("Error assigning DSA key to EVP_PKEY structure.");
   }

   else if(strcmp(keytype, "ecc") == 0) {
      myecc = EC_KEY_new();
      int eccgrp = OBJ_txt2nid(eccstrength);
      myecc = EC_KEY_new_by_curve_name(eccgrp);
      /* Important to set the OPENSSL_EC_NAMED_CURVE flag,    *
       * otherwise the cert will not work with an SSL server. */
      EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
      if (! (EC_KEY_generate_key(myecc)))
         int_error("Error generating the ECC key.");

      if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
         int_error("Error assigning ECC key to EVP_PKEY structure.");
   }
   else
      int_error("Error: Wrong keytype - choose either RSA, DSA or ECC.");

   if(cgiFormString("sigalg", sigalgstr, sizeof(sigalgstr)) != cgiFormSuccess)
      int_error("Error getting the signature algorithm from buildrequestbuildrequest.cgi form");

/* ------------------------------------------------------------------------- *
 * Generate the certificate request from scratch                             *
 * ------------------------------------------------------------------------- */
   if ((webrequest=X509_REQ_new()) == NULL)
      int_error("Error creating new X509_REQ structure.");

   if (X509_REQ_set_pubkey(webrequest, pkey) == 0)
      int_error("Error setting public key for X509_REQ structure.");

   if ((reqname=X509_REQ_get_subject_name(webrequest)) == NULL)
      int_error("Error setting public key for X509_REQ structure.");

   /* The following functions create and add the entries, working out  *
    * the correct string type and performing checks on its length.     *
    * We also check the return value for errors...                     */

   if(strlen(country) != 0)
      X509_NAME_add_entry_by_txt(reqname,"C", MBSTRING_UTF8, 
                           (unsigned char*) country, -1, -1, 0);
   if(strlen(province) != 0)
      X509_NAME_add_entry_by_txt(reqname,"ST", MBSTRING_UTF8,
                           (unsigned char *) province, -1, -1, 0);
   if(strlen(locality) != 0)
      X509_NAME_add_entry_by_txt(reqname,"L", MBSTRING_UTF8,
                          (unsigned char *) locality, -1, -1, 0);
   if(strlen(organisation) != 0)
      X509_NAME_add_entry_by_txt(reqname,"O", MBSTRING_UTF8,
                      (unsigned char *) organisation, -1, -1, 0);
   if(strlen(department) != 0)
      X509_NAME_add_entry_by_txt(reqname,"OU", MBSTRING_UTF8,
                         (unsigned char *) department, -1, -1, 0);
   if(strlen(email_addr) != 0)
      X509_NAME_add_entry_by_txt(reqname,"emailAddress", MBSTRING_UTF8,
			(unsigned char *)  email_addr, -1, -1, 0);
   if(strlen(cname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_UTF8,
                                   (unsigned char *) cname, -1, -1, 0);
   if(strlen(surname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"SN", MBSTRING_UTF8,
                                   (unsigned char *) surname, -1, -1, 0);
   if(strlen(givenname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"GN", MBSTRING_UTF8,
                                 (unsigned char *) givenname, -1, -1, 0);

#ifdef FORCE_SOURCE_IP_INCLUSION
   char dns_name[255];
   snprintf(dns_name, sizeof(dns_name), "ReqIP %s [%s]", cgiRemoteAddr,
                                                        get_dns(cgiRemoteAddr));
   X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_UTF8,
                              (unsigned char *) dns_name, -1, -1, 0);
#endif

/* ------------------------------------------------------------------------- *
 * If provided, add SubjectAltName data to the request as a extension        *
 * ------------------------------------------------------------------------- */
   if (strlen(datasan1) != 0 || strlen(datasan2) != 0 ||
       strlen(datasan3) != 0 || strlen(datasan4) != 0) {
      X509_EXTENSION *ext;
      char subaltname[4096] = "";

      if (strlen(typesan1) != 0 && strlen(datasan1) != 0)
         snprintf(subaltname, sizeof(subaltname), "%s:%s", typesan1, datasan1);

      if (strlen(typesan2) != 0 && strlen(datasan2) != 0) {
         if (strcmp(subaltname, "") != 0)
            strncat(subaltname, ", ", sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, typesan2, sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, ":", sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, datasan2, sizeof(subaltname) - strlen(subaltname));
      }

      if (strlen(typesan3) != 0 && strlen(datasan3) != 0) {
         if (strcmp(subaltname, "") != 0)
            strncat(subaltname, ", ", sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, typesan3, sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, ":", sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, datasan3, sizeof(subaltname) - strlen(subaltname));
      }

      if (strlen(typesan4) != 0 && strlen(datasan4) != 0) {
         if (strcmp(subaltname, "") != 0)
            strncat(subaltname, ", ", sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, typesan4, sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, ":", sizeof(subaltname) - strlen(subaltname));
         strncat(subaltname, datasan4, sizeof(subaltname) - strlen(subaltname));
      }

      /* creating the extension object NID_subject_alt_name */
      ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, subaltname);
      if (ext == NULL ) int_error("Error creating X509 extension object");
     
      /* add the extension to the stack */
      X509v3_add_ext(&ext_list, ext, -1);
      X509_EXTENSION_free(ext);

      /* add the stack to the request */
      X509_REQ_add_extensions(webrequest, ext_list);
      //if (X509_REQ_add_extensions(webrequest, ext_list) != 0)
      //   int_error("Error adding extensions to the X509_REQ structure.");
   }

/* -------------------------------------------------------------------------- *
 *  Set the digest algorithm for signing                                      *
 * if (EVP_PKEY_type(ca_privkey->type) == EVP_PKEY_DSA)                       *
 *   digest = EVP_dss1(); we used to sign ecc keys, switched to SHA variants  *
 * ---------------------------------------------------------------------------*/
   if(strcmp(sigalgstr, "SHA-224") == 0) digest = EVP_sha224();
   else if(strcmp(sigalgstr, "SHA-256") == 0) digest = EVP_sha256();
   else if(strcmp(sigalgstr, "SHA-384") == 0) digest = EVP_sha384();
   else if(strcmp(sigalgstr, "SHA-512") == 0) digest = EVP_sha512();
   else int_error("Error received unknown sigalg string");


/* ------------------------------------------------------------------------- *
 * Sign the certificate request                                              *
 * ------------------------------------------------------------------------- */
   if (!X509_REQ_sign(webrequest, pkey, digest))
      int_error("Error signing X509_REQ structure with SHA256.");

/* ------------------------------------------------------------------------- *
 *  and sort out the content plus start the html output                      *
 * ------------------------------------------------------------------------- */
   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   display_csr(webrequest);
   fprintf(cgiOut, "<p></p>\n");

   display_signing(webrequest);

   fprintf(cgiOut, "<p></p>\n");
   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "The auto-generated Private Key:</th></tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td class=\"getcert\">\n");
   fprintf(cgiOut, "<a href=\"javascript:elementHideShow('keypem');\">\n");
   fprintf(cgiOut, "Expand/Hide Private Key data in PEM format</a>\n");
   fprintf(cgiOut, "<div class=\"showpem\" id=\"keypem\"  style=\"display: block\"\n>");
   fprintf(cgiOut, "<pre>\n");

   if (! PEM_write_PrivateKey(cgiOut,pkey,NULL,NULL,0,0,NULL)) {
         int_error("Error printing the private key");
   }

   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "Copy and save this key data to file for use with the certificate.</th></tr>\n");
   fprintf(cgiOut, "</table>\n");

   pagefoot();
   BIO_free(outbio);
   return(0);
}
