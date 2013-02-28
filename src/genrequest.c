/* -------------------------------------------------------------------------- *
 * file:	genrequest.cgi                                                *
 * purpose:	takes the input from buildrequest.cgi and generates request   *
 *              plus public/private key pair                                  *
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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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
   EVP_PKEY	  *pkey		 = NULL;
   X509_NAME 	*reqname	 = NULL;
   DSA 		*mydsa		 = NULL;
   RSA 		*myrsa		 = NULL;
   BIO 		*outbio		 = NULL;
   X509_NAME_ENTRY      *e;
   STACK_OF(X509_EXTENSION) 
                       *ext_list = NULL;
   int          i;

   char         buf[80]		 = "";
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
   time_t       now              = 0;
   struct tm    *tm;
   char         startdate[11]    ="";
   char         enddate[11]      ="";
   char         starttime[9]     ="";
   char         endtime[9]       ="";

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

/* we do not accept requests with no data, i.e. being empty with just a 
   public key. Although technically possible to sign and create a cert,
   they don't make much sense. We require here at least one CN supplied.    */

   if(strlen(cname) == 0)
     int_error("No CN has been provided. The CN field is mandatory.");

/* ------------------------------------------------------------------------ *
 * Calculate default date and time strings                                  *
 * ------------------------------------------------------------------------ */
   now = time(NULL);
   tm = gmtime(&now);

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

/* ------------------------------------------------------------------------ *
 * These function calls are essential to make many PEM + other openssl      *
 * functions work.                                                          *
 * ------------------------------------------------------------------------ */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

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
   else
      int_error("Error: Wrong keytype - choose either RSA or DSA.");

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
   snprintf(dns_name, sizeof(dns_name), "ReqIP %s [%s]", cgiRemoteAddr,
                                                        get_dns(cgiRemoteAddr));
   X509_NAME_add_entry_by_txt(reqname,"CN", MBSTRING_UTF8,
                              (unsigned char *) dns_name, -1, -1, 0);
//   X509_NAME_add_entry_by_NID(reqname, 41, MBSTRING_UTF8,
//                              (unsigned char *) dns_name, -1, -1, 0);
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

/* ------------------------------------------------------------------------- *
 * Sign the certificate request: md5 for RSA keys, dss for DSA keys          *
 * ------------------------------------------------------------------------- */

   if(strcmp(keytype, "rsa") == 0) {
      if (!X509_REQ_sign(webrequest,pkey,EVP_md5()))
         int_error("Error MD5 signing X509_REQ structure.");
   }
   else if(strcmp(keytype, "dsa") == 0) {
      if (!X509_REQ_sign(webrequest,pkey,EVP_dss()))
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
      fprintf(cgiOut, "<td class=type180>");
      fprintf(cgiOut, "%s</td>", buf);
      fprintf(cgiOut, "<td>");
      ASN1_STRING_print_ex(outbio, e->value, ASN1_STRFLGS_UTF8_CONVERT);
      fprintf(cgiOut, "</td>");
      fprintf(cgiOut, "</tr>\n");
   }

   /* If our certificate request includes extensions, we display here */
   if ((ext_list = X509_REQ_get_extensions(webrequest)) != NULL) {
     fprintf(cgiOut, "<tr>");
     fprintf(cgiOut, "<th colspan=\"2\">");
     fprintf(cgiOut, "Extensions within this certificate request: %d", sk_X509_EXTENSION_num(ext_list));
     fprintf(cgiOut, "</th>");
     fprintf(cgiOut, "</tr>\n");

     /* display the cert extension list here */
     for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ext;

        ext = sk_X509_EXTENSION_value(ext_list, i);
        obj = X509_EXTENSION_get_object(ext);

        fprintf(cgiOut, "<tr>");
        fprintf(cgiOut, "<td class=type180>");
        i2a_ASN1_OBJECT(outbio, obj);
        fprintf(cgiOut, "</td>");

        fprintf(cgiOut, "<td>");
        if (!X509V3_EXT_print(outbio, ext, 0, 0)) {
        /* Some extensions (i.e. LogoType) have no handling    *
         * defined, we need to print their content as hex data */
          fprintf(cgiOut, "%*s", 0, "");
          M_ASN1_OCTET_STRING_print(outbio, ext->value);
        }
        fprintf(cgiOut, "</td>");
        fprintf(cgiOut, "</tr>\n");
     }
   }

  /* display the key type and size here */
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th colspan=2>Public key data for this certificate request:");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "<td colspan=2 class=getcert>");
  if (pkey) {
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(stdout, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(stdout, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      default:
        fprintf(stdout, "%d bit non-RSA/DSA Key", EVP_PKEY_bits(pkey));
        break;
    }
  }

  fprintf(cgiOut, " <a href=\"javascript:elementHideShow('pubkey');\">\n");
  fprintf(cgiOut, "Expand or Hide Public Key Data</a>\n");
  /* display the public key data in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"pubkey\" style=\"display: none\">");
  fprintf(cgiOut, "<pre>\n");
  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");
  fprintf(cgiOut, "</pre>\n");
  fprintf(cgiOut, "</div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "&nbsp;");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");
  fprintf(cgiOut, "<p></p>\n");

   /* Add Certificate extensions, Define validity */
   fprintf(cgiOut, "<table width=100%%>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"3\">");
   fprintf(cgiOut, "Define certificate details:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   /* Add Key Usage */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"checkbox\" name=\"keyusage\" checked id=\"key_cb\" onclick=\"switchGrey('key_cb', 'key_td', 'none');\" />");
   fprintf(cgiOut, "</th>");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Key Usage:</td>");
   fprintf(cgiOut, "<td id=\"key_td\" style=\"padding: 0;\">");
   fprintf(cgiOut, "<table style=\"width: 100%%; border-style: none;\"><tr><td>");
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
   fprintf(cgiOut, "</td></tr></table></td></tr>");

   /* Add extended key usage */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"checkbox\" name=\"extkeyusage\" id=\"exkey_cb\" onclick=\"switchGrey('exkey_cb', 'exkey_td', 'none');\" />");
   fprintf(cgiOut, "</th>");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Extended Key Usage:");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "<td id=\"exkey_td\" style=\"background-color: #CFCFCF;\">");
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
   fprintf(cgiOut, "</tr>\n");

   /* Set validity from now */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"days_cb\" value=vd checked onclick=\"switchGrey('days_cb', 'days_td', 'date_td');\" />");
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

   /* Set validity by date, format */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=radio name=\"valid\" id=\"date_cb\" value=se onclick=\"switchGrey('date_cb', 'date_td', 'days_td')\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Set Validity (by Date):");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td id=\"date_td\" style=\"background-color: #CFCFCF;\">");
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
   fprintf(cgiOut, "<th colspan=\"3\">");
   fprintf(cgiOut, "<input type=\"button\" name=\"Forget it!\" value=");
   fprintf(cgiOut, "\"  Go Back  \" onclick=");
   fprintf(cgiOut, "\"self.location.href='buildrequest.cgi'\">&nbsp;");
   fprintf(cgiOut, "&nbsp;<input type=\"button\" value=\"Print Page\" ");
   fprintf(cgiOut, "onclick=\"print(); return false;\">&nbsp;");
   fprintf(cgiOut, "&nbsp;<input type=\"submit\" value=\"Sign Request\">");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "</form>");

   fprintf(cgiOut, "<table width=100%%>");

   /* display the request content in PEM format here */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Show certificate request data in PEM format:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"getcert\">");
   fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqpem');\">\n");
   fprintf(cgiOut, "Expand/Hide Request data in PEM format</a>\n");
   fprintf(cgiOut, "<div class=\"showpem\" id=\"reqpem\"  style=\"display: none\">\n");
   fprintf(cgiOut, "<pre>\n");
   PEM_write_bio_X509_REQ(outbio, webrequest);
   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   if(strcmp(keytype, "rsa") == 0) 
      fprintf(cgiOut, "Private Key Pair - %d Bit RSA:</th></tr>\n", rsastrength);
   if(strcmp(keytype, "dsa") == 0) 
      fprintf(cgiOut, "Private Key Pair - %d Bit DSA:</th></tr>\n", dsastrength);
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
