/* -------------------------------------------------------------------------- *
 * file:	genrequest.cgi                                                *
 * purpose:	takes the input from buildrequest.cgi and generates request   *
 *              and public/private key pair                                   *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "webcert.h"

char dns_name[255];

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
   EVP_PKEY	*pubkey		 = NULL;
   X509_NAME 	*reqname	 = NULL;
   DSA 		*mydsa		 = NULL;
   RSA 		*myrsa		 = NULL;
   BIO 		*outbio		 = NULL;
   X509_NAME_ENTRY      *e;
   int                  i;

   char         buf[80]		 = "";
   char         country[81]      = "";
   char         province[81]     = "";
   char         locality[81]     = "";
   char         organisation[81] = "";
   char         department[81]   = "";
   char 	email_addr[81]   = "";
   char 	cname0[81]       = "";
   char 	cname1[81]       = "";
   char 	cname2[81]       = "";
   char 	surname[81]      = "";
   char 	givenname[81]    = "";

   char 	keytype[81]      = "";
   int	 	rsastrength	 = 0;
   int	 	dsastrength	 = 0;

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
   cgiFormString("cn0", cname0, sizeof(cname0));
   cgiFormString("cn1", cname1, sizeof(cname1));
   cgiFormString("cn2", cname2, sizeof(cname2));
   cgiFormString("sn", surname, sizeof(surname));
   cgiFormString("gn", givenname, sizeof(givenname));

   cgiFormString("keytype", keytype, sizeof(keytype));
   cgiFormInteger("rsastrength", &rsastrength, 0);
   cgiFormInteger("dsastrength", &dsastrength, 0);

/* we do not accept requests with no data, i.e. being empty with just a 
   public key. Although technically possible to sign and create a cert,
   they don't make much sense. We require here at least one CN supplied.    */

   if(strlen(cname0) == 0 && strlen(cname1) == 0 && strlen(cname2) == 0)
     int_error("Error supply at least one CNAME in request subject");

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work. It is not well documented, I found out after looking into  *
 * the openssl source directly.                                               *
 * needed by: PEM_read_PrivateKey(), X509_REQ_verify() ...                    *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

/* ------------------------------------------------------------------------- *
 * Generate the key pair based on the selected keytype                       *
 * ------------------------------------------------------------------------- */

   if ((pubkey=EVP_PKEY_new()) == NULL)
      int_error("Error creating EVP_PKEY structure.");

   if(strcmp(keytype, "rsa") == 0) {

      myrsa = RSA_new();
      if (! (myrsa = RSA_generate_key(rsastrength, RSA_F4, NULL, NULL)))
         int_error("Error generating the RSA key.");

      if (!EVP_PKEY_assign_RSA(pubkey,myrsa))
         int_error("Error assigning RSA key to EVP_PKEY structure.");
   }
   else if(strcmp(keytype, "dsa") == 0) {

      mydsa = DSA_new();
      mydsa = DSA_generate_parameters(dsastrength, NULL, 0, NULL, NULL,
                                                                  NULL, NULL);
      if (! (DSA_generate_key(mydsa)))
         int_error("Error generating the DSA key.");

      if (!EVP_PKEY_assign_DSA(pubkey,mydsa))
         int_error("Error assigning DSA key to EVP_PKEY structure.");
   }
   else
      int_error("Error: Wrong keytype - choose either RSA or DSA.");

/* ------------------------------------------------------------------------- *
 * Generate the certificate request from scratch                             *
 * ------------------------------------------------------------------------- */

   if ((webrequest=X509_REQ_new()) == NULL)
      int_error("Error creating new X509_REQ structure.");

   if (X509_REQ_set_pubkey(webrequest, pubkey) == 0)
      int_error("Error setting public key for X509_REQ structure.");

   if ((reqname=X509_REQ_get_subject_name(webrequest)) == NULL)
      int_error("Error setting public key for X509_REQ structure.");

   /* The following functions create and add the entries, working out  *
    * the correct string type and performing checks on its length.     *
    * We also check the return value for errors...                     */

   if(strlen(country) != 0)
      X509_NAME_add_entry_by_txt(reqname,"C", MBSTRING_ASC, 
                           (unsigned char*) country, -1, -1, 0);
   if(strlen(province) != 0)
      X509_NAME_add_entry_by_txt(reqname,"ST", MBSTRING_ASC,
                           (unsigned char *) province, -1, -1, 0);
   if(strlen(locality) != 0)
      X509_NAME_add_entry_by_txt(reqname,"L", MBSTRING_ASC,
                          (unsigned char *) locality, -1, -1, 0);
   if(strlen(organisation) != 0)
      X509_NAME_add_entry_by_txt(reqname,"O", MBSTRING_ASC,
                      (unsigned char *) organisation, -1, -1, 0);
   if(strlen(department) != 0)
      X509_NAME_add_entry_by_txt(reqname,"OU", MBSTRING_ASC,
                         (unsigned char *) department, -1, -1, 0);
   if(strlen(email_addr) != 0)
      X509_NAME_add_entry_by_txt(reqname,"emailAddress", MBSTRING_ASC,
			(unsigned char *)  email_addr, -1, -1, 0);
   if(strlen(cname0) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                                   (unsigned char *) cname0, -1, -1, 0);
   if(strlen(cname1) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                                   (unsigned char *) cname1, -1, -1, 0);
   if(strlen(cname2) != 0)
      X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                                   (unsigned char *) cname2, -1, -1, 0);
   if(strlen(surname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"SN", MBSTRING_ASC,
                                   (unsigned char *) surname, -1, -1, 0);
   if(strlen(givenname) != 0)
      X509_NAME_add_entry_by_txt(reqname,"GN", MBSTRING_ASC,
                                 (unsigned char *) givenname, -1, -1, 0);

#ifdef FORCE_SOURCE_IP_INCLUSION
   snprintf(dns_name, sizeof(dns_name), "ReqIP %s [%s]", cgiRemoteAddr,
                                                        get_dns(cgiRemoteAddr));
   X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_ASC,
                              (unsigned char *) dns_name, -1, -1, 0);
//   X509_NAME_add_entry_by_NID(reqname, 41, MBSTRING_ASC,
//                              (unsigned char *) dns_name, -1, -1, 0);
#endif

/* ------------------------------------------------------------------------- *
 * Sign the certificate request: md5 for RSA keys, dss for DSA keys          *
 * ------------------------------------------------------------------------- */

   if(strcmp(keytype, "rsa") == 0) {
      if (!X509_REQ_sign(webrequest,pubkey,EVP_md5()))
         int_error("Error MD5 signing X509_REQ structure.");
   }
   else if(strcmp(keytype, "dsa") == 0) {
      if (!X509_REQ_sign(webrequest,pubkey,EVP_dss()))
         int_error("Error DSS signing X509_REQ structure.");
   }

/* ------------------------------------------------------------------------- *
 *  and sort out the content plus start the html output                      *
 * ------------------------------------------------------------------------- */

   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   fprintf(cgiOut, "<form action=\"certsign.cgi\" method=\"post\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cert-request\" ");
   fprintf(cgiOut, "value=\"");
   if (! PEM_write_bio_X509_REQ(outbio, webrequest))
      int_error("Error printing the request");
   fprintf(cgiOut, "\">\n");
   fprintf(cgiOut, "<table width=100%%>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Subject data of this certificate request:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");

   for (i = 0; i < X509_NAME_entry_count(reqname); i++) {
      e = X509_NAME_get_entry(reqname, i);
      OBJ_obj2txt(buf, 80, e->object, 0);

      fprintf(cgiOut, "<tr>");
      fprintf(cgiOut, "<td width=\"200\" bgcolor=\"#CFCFCF\">");
      fprintf(cgiOut, "%s%s", buf ,"</td>");
      fprintf(cgiOut, "<td>");
      fprintf(cgiOut, "%s", e->value->data);
      fprintf(cgiOut, "</td>");
      fprintf(cgiOut, "</tr>");
   }

   /* Certificate Settings Header */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Define Certificate Details:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   /* Certificate Settings start here */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td  rowspan=5 align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "Set Key Usage:</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=sv checked>");
   fprintf(cgiOut, " SSL Server</td></tr><tr>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=cl>");
   fprintf(cgiOut, " SSL Client</td></tr><tr>\n");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=em>");
   fprintf(cgiOut, " E-Mail Encryption ");
   fprintf(cgiOut, "<input type=text size=18 name=\"ename\">");
   fprintf(cgiOut, " Address</td></tr><tr>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=os>");
   fprintf(cgiOut, " Object Signing</td></tr><tr>\n");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=ca>");
   fprintf(cgiOut, " CA Certificate</td></tr>");

   /* extended key usage information */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "Set Extended Key Usage:");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"checkbox\" name=\"extkeyusage\">");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "<select name=\"extkeytype\">");
   fprintf(cgiOut, "<option value=\"tlsws\" selected>");
   fprintf(cgiOut, "TLS Web server authentication</option>");
   fprintf(cgiOut, "<option value=\"tlscl\">TLS Web client authentication</option>");
   fprintf(cgiOut, "<option value=\"cs\">Code Signing</option>");
   fprintf(cgiOut, "<option value=\"ep\">Email Protection</option>");
   fprintf(cgiOut, "<option value=\"ts\">Time Stamping</option>");
   fprintf(cgiOut, "<option value=\"ocsp\">OCSP Signing</option>");
   fprintf(cgiOut, "</select>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr><td align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "Set Expiration Date:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=text name=\"edate\" size=4 value=%d>", DAYS_VALID);
   fprintf(cgiOut, " Days until Expiration");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "<input type=\"button\" name=\"Forget it!\" value=");
   fprintf(cgiOut, "\"  Go Back  \" onClick=");
   fprintf(cgiOut, "\"self.location.href='buildrequest.cgi'\">&nbsp;");
   fprintf(cgiOut, "&nbsp;<input type=\"submit\" value=\"Sign Request\">");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "</form>");

   fprintf(cgiOut, "<table width=100%%>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "Private Key (%s):</th></tr>\n", keytype);
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td class=\"getcert\">\n");
   fprintf(cgiOut, "<pre>\n");
   fprintf(cgiOut, "<div id=\"getpem\">\n");

   if (! PEM_write_PrivateKey(cgiOut,pubkey,NULL,NULL,0,0,NULL)) {
         int_error("Error printing the private key");
   }

   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "</textarea></form>\n");
   fprintf(cgiOut, "</td></tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "Copy and save to file for use with the certificate.</th></tr>\n");
   fprintf(cgiOut, "</table>");
   pagefoot();
   BIO_free(outbio);
   return(0);
}
