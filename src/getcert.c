/* -------------------------------------------------------------------------- *
 * file:         getcert.c                                                    *
 * purpose:      display the certificate from file                            *
 * hint:         call it with ?cfilename=cacert to display the root CA cert   *
 * -------------------------------------------------------------------------- */

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "webcert.h"

int cgiMain() {

   X509			*cert;
   BIO			*outbio;
   char			format[5]         = "";
   char 		certfilepath[255] = "";
   char 		expfilepath[255]  = "";
   char 		pemfileurl[255]   = "";
   char 		derfileurl[255]   = "";
   char 		p12fileurl[255]   = "";
   char                 certnamestr[81]   = "";
   char 		certfilestr[81]   = "[n/a]";
   FILE 		*certfile         = NULL;

   /* the title can't be static because we possibly change it for the CA cert */
   char 		title[41] = "Display Certificate";

   if (! (cgiFormString("cfilename", certfilestr, sizeof(certfilestr)) == cgiFormSuccess))
      int_error("Error getting >cfilename< from calling form");

   if (cgiFormString("format", format, sizeof(format)) == cgiFormSuccess) {
      if (! (strcmp(format, "text") || strcmp(format, "pem")))
         int_error("Error getting correct format parameter in URL");
   }
   else strcpy(format, "pem");

/* -------------------------------------------------------------------------- *
 * Since we gonna display the file, we must make sure no "../../.." is passed *
 * from the calling URL or else sensitive files could be read and we have a   *
 * huge security problem. We scan and must reject all occurrences of '..' '/' *
 * ---------------------------------------------------------------------------*/

   if ( strstr(certfilestr, "..") ||
        strchr(certfilestr, '/')  ||
        (! strstr(certfilestr, ".pem")) )
      int_error("Error incorrect data in >cfilename<");

/* -------------------------------------------------------------------------- *
 * check if should display the CA cert, or open the requested filename        *
 * ---------------------------------------------------------------------------*/

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

/* -------------------------------------------------------------------------- *
 * decode the certificate and define BIO output stream                        *
 * ---------------------------------------------------------------------------*/

   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   if (! (cert = PEM_read_X509(certfile,NULL,NULL,NULL)))
      int_error("Error loading cert into memory");

/* -------------------------------------------------------------------------- *
 * strip off the file format extension from the file name                     *
 * ---------------------------------------------------------------------------*/

   strncpy(certnamestr, certfilestr, sizeof(certnamestr));
   strtok(certnamestr, ".");

/* -------------------------------------------------------------------------- *
 * check if there are exported pem|der|p12 versions of this certificate       *
 * ---------------------------------------------------------------------------*/
   snprintf(expfilepath, sizeof(expfilepath), "%s/%s.pem",
                           CERTEXPORTDIR, certnamestr);

   if (fopen(expfilepath, "r"))
      snprintf(pemfileurl, sizeof(pemfileurl), "%s/%s.pem",
                           CERTEXPORTURL, certnamestr);

   snprintf(expfilepath, sizeof(expfilepath), "%s/%s.der",
                           CERTEXPORTDIR, certnamestr);

   if (fopen(expfilepath, "r"))
      snprintf(derfileurl, sizeof(derfileurl), "%s/%s.der",
                           CERTEXPORTURL, certnamestr);

   snprintf(expfilepath, sizeof(expfilepath), "%s/%s.p12",
                           CERTEXPORTDIR, certnamestr);

   if (fopen(expfilepath, "r"))
      snprintf(p12fileurl, sizeof(p12fileurl), "%s/%s.p12",
                           CERTEXPORTURL, certnamestr);

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/
   pagehead(title);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/
   fprintf(cgiOut, "<table width=\"100%%\">\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "certificate %s in PEM format", certfilestr);
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"getcert\">");
   fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certpem');\">\n");
   fprintf(cgiOut, "Expand/Hide certificate data in PEM format</a>\n");

   if (strcmp(format, "pem") == 0)
      fprintf(cgiOut, "<div class=\"showpem\" id=\"certpem\" style=\"display: block\">\n");
   else 
      fprintf(cgiOut, "<div class=\"showpem\" id=\"certpem\" style=\"display: none\">\n");

   fprintf(cgiOut, "<pre>\n");
   if (! PEM_write_bio_X509(outbio, cert))
      int_error("Error printing the certificate");
   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "certificate %s in Text format", certfilestr);
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td class=\"getcert\">\n");
   fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certtext');\">\n");
   fprintf(cgiOut, "Expand/Hide certificate data in Text format</a>\n");

   if (strcmp(format, "text") == 0)
      fprintf(cgiOut, "<div class=\"showtext\" id=\"certtext\"  style=\"display: block\">\n");
   else 
      fprintf(cgiOut, "<div class=\"showtext\" id=\"certtext\"  style=\"display: none\">\n");

   fprintf(cgiOut, "<pre>\n");
   if (! (X509_print_ex_fp(cgiOut, cert,
          XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB), X509_FLAG_COMPAT)))
      int_error("Error printing certificate text information");

   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "<p></p>\n");

   fprintf(cgiOut, "<table width=\"100%%\">\n");
   fprintf(cgiOut, "<tr>\n");

   // Show PEM format
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Show PEM\" />\n");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\" />\n");
   fprintf(cgiOut, "</form>\n");
   fprintf(cgiOut, "</th>\n");

   // Show Text format
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Show Text\" />\n");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"text\" />\n");
   fprintf(cgiOut, "</form>\n");
   fprintf(cgiOut, "</th>\n");

   // Print View
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<input type=\"button\" value=\"Print Page\" ");
   fprintf(cgiOut, "onclick=\"print(); return false;\" />");
   fprintf(cgiOut, "</th>\n");

   if (strlen(p12fileurl) == 0) {
     fprintf(cgiOut, "<th>\n");
     fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">\n");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Export P12\" />\n");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
     fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
     fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"p12\" />\n");
     fprintf(cgiOut, "</form>\n");
     fprintf(cgiOut, "</th>\n");
   }
   else {
     fprintf(cgiOut, "<th>\n");
     fprintf(cgiOut, "<input type=\"button\" value=\"Get P12\" ");
     fprintf(cgiOut, "onclick=\"self.location.href='%s'\" />\n", p12fileurl);
     fprintf(cgiOut, "</th>\n");
   }

   if (strlen(pemfileurl) == 0) {
     fprintf(cgiOut, "<th>\n");
     fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">\n");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Export PEM\" />\n");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
     fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
     fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\" />\n");
     fprintf(cgiOut, "</form>\n");
     fprintf(cgiOut, "</th>\n");
   }
   else {
     fprintf(cgiOut, "<th>\n");
     fprintf(cgiOut, "<input type=\"button\" value=\"Get PEM\" ");
     fprintf(cgiOut, "onclick=\"self.location.href='%s'\" />", pemfileurl);
     fprintf(cgiOut, "</th>\n");
   }

   if (strlen(derfileurl) == 0) {
     fprintf(cgiOut, "<th>\n");
     fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">\n");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Export DER\" />\n");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
     fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
     fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"der\" />\n");
     fprintf(cgiOut, "</form>\n");
     fprintf(cgiOut, "</th>\n");
   }
   else {
     fprintf(cgiOut, "<th>\n");
     fprintf(cgiOut, "<input type=\"button\" value=\"Get DER\" ");
     fprintf(cgiOut, "onclick=\"self.location.href='%s'\" />\n", derfileurl);
     fprintf(cgiOut, "</th>\n");
   }
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "</table>\n");
   pagefoot();
   BIO_free(outbio);
   return(0);
}
