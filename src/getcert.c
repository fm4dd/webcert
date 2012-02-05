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
   X509_NAME		*certname;
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

   fprintf(cgiOut, "<table width=100%%>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "certificate %s in %s format", certfilestr, format);
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"getcert\">\n");
   fprintf(cgiOut, "<pre>\n");

   if (strcmp(format, "pem") == 0) {
      fprintf(cgiOut, "<div id=\"getpem\">\n");

      if (! PEM_write_bio_X509(outbio, cert))
         int_error("Error printing the certificate");
   }

   if (strcmp(format, "text") == 0) {
      fprintf(cgiOut, "<div id=\"gettext\">\n");

      if (! (certname = X509_get_subject_name(cert)))
         int_error("Error getting subject data from certificate");
      //if (! (X509_NAME_print_ex(outbio, certname, 3)))
      if (! (X509_print_ex(outbio, cert, 0, XN_FLAG_SEP_MULTILINE)))
         int_error("Error printing certificate text information");

   }
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "<p></p>\n");

   fprintf(cgiOut, "<table width=100%%>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Show PEM\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfilestr);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\">");
   fprintf(cgiOut, "</th></form>\n");

   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Show Text\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\">", certfilestr);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"text\">");
   fprintf(cgiOut, "</th></form>\n");

   // filler 1 separating view from download
   fprintf(cgiOut, "<th width=100>");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</th>\n");

   if (strlen(p12fileurl) == 0) {
     fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
     fprintf(cgiOut, "<th>");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Export P12\">");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
     fprintf(cgiOut, "value=\"%s\">", certfilestr);
     fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"p12\">");
     fprintf(cgiOut, "</th></form>\n");
   }
   else {
     fprintf(cgiOut, "<th>");
     fprintf(cgiOut, "<input type=\"button\" value=\"Get P12\" ");
     fprintf(cgiOut, "onClick=\"self.location.href='%s'\">", p12fileurl);
     fprintf(cgiOut, "</th>");
   }

   if (strlen(pemfileurl) == 0) {
     fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
     fprintf(cgiOut, "<th>");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Export PEM\">");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
     fprintf(cgiOut, "value=\"%s\">", certfilestr);
     fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\">");
     fprintf(cgiOut, "</th></form>\n");
   }
   else {
     fprintf(cgiOut, "<th>");
     fprintf(cgiOut, "<input type=\"button\" value=\"Get PEM\" ");
     fprintf(cgiOut, "onClick=\"self.location.href='%s'\">", pemfileurl);
     fprintf(cgiOut, "</th>");
   }

   if (strlen(derfileurl) == 0) {
     fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
     fprintf(cgiOut, "<th>");
     fprintf(cgiOut, "<input type=\"submit\" value=\"Export DER\">");
     fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
     fprintf(cgiOut, "value=\"%s\">", certfilestr);
     fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"der\">");
     fprintf(cgiOut, "</th></form>\n");
   }
   else {
     fprintf(cgiOut, "<th>");
     fprintf(cgiOut, "<input type=\"button\" value=\"Get DER\" ");
     fprintf(cgiOut, "onClick=\"self.location.href='%s'\">", derfileurl);
     fprintf(cgiOut, "</th>");
   }
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "</table>\n");
   pagefoot();
   BIO_free(outbio);
   return(0);
}
