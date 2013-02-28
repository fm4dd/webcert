/* -------------------------------------------------------------------------- *
 * file:	certverify.cgi                                                *
 * purpose:	verify the certificate entries before signing                 *
 * compile:     gcc -I/usr/local/ssl/include -L/usr/local/ssl/lib             *
 * certverify.c -o certverify.cgi -lcgic -lssl -lcrypto                       *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cgic.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "webcert.h"

int cgiMain() {

   BIO 			    *inbio   = NULL;
   BIO                      *outbio  = NULL;
   X509_REQ 		*webrequest  = NULL;
   EVP_PKEY                   *pkey  = NULL;
   X509_NAME 		   *reqname  = NULL;
   X509_NAME_ENTRY 	*e;
   STACK_OF(X509_EXTENSION)
                       *ext_list = NULL;
   int 			i;
   char 		buf[80] = "";
   char 		formreq[REQLEN] = "";
   char 		reqtest[REQLEN] = "";
   char 		beginline[81]   = "";
   char 		endline[81]     = "";
   char                 *char_pos       = NULL;
   static char 		title[] = "Verify Request";

   int                  filesize = 0;
   cgiFilePtr		file;
   time_t       now              = 0;
   struct tm    *tm;
   char         startdate[11]    ="";
   char         enddate[11]      ="";
   char         starttime[9]     ="";
   char         endtime[9]       ="";

/* ------------------------------------------------------------------------- *
 * check if a certificate request was handed to certverify.cgi               *
 * or if someone just tried to call us directly without a request            *
 * --------------------------------------------------------------------------*/

   if (! (cgiFormString("cert-request", formreq, REQLEN) == cgiFormSuccess )) {
   /* we did not get a cert-request pasted, let's see if we got a file */
      if (! (cgiFormFileSize("requestfile", &filesize) == cgiFormSuccess)) {
         /* if we did not get a file either, we report failure */
         int_error("Error getting request from certrequest.cgi form");
      } else {
         /* we got a file, check the size is between 0 and REQLEN */
         if (filesize <=0 || filesize > REQLEN)
            int_error("Error uploaded request file size is to big");
         else
            /* we open the file to get a file handle */
            cgiFormFileOpen( "requestfile", &file);
            /* we read the file content into our formreq buffer */
            if (! (cgiFormFileRead(file, formreq, REQLEN, &filesize) == cgiFormSuccess))
               int_error("Error uploaded request file is not readable");
      }
   }

/* ------------------------------------------------------------------------- *
 * check if a certificate was pasted or if someone just typed                *
 * a line of garbage                                                         *
 * --------------------------------------------------------------------------*/

   if (! strchr(formreq, '\n'))
      int_error("Error invalid request format, received garbage line");

/* ------------------------------------------------------------------------- *
 * check if a certificate was pasted with the BEGIN and END                  *
 * lines, assuming the request in between is intact                          *
 * ------------------------------------------------------------------------- */

   strcpy(reqtest, formreq);
   strcpy(endline, (strrchr(reqtest, '\n') +1));
   /* should there be a extra newline at the end, we remove it here */
   if(strlen(endline) == 0 && strlen(reqtest) > 0) {
      reqtest[strlen(reqtest)-1]='\0';
      strcpy(endline, (strrchr(reqtest, '\n') +1));
   }
   strtok(reqtest, "\n");
   strcpy(beginline, reqtest);

   /* should there be a windows carriage return, we remove it here */
   if ((char_pos = strchr(beginline, '\r'))) *char_pos='\0';
   if ((char_pos = strchr(endline, '\r'))) *char_pos='\0';

   if(! ( (strcmp(beginline, "-----BEGIN CERTIFICATE REQUEST-----") == 0 &&
         strcmp(endline, "-----END CERTIFICATE REQUEST-----") == 0)
         ||

        (strcmp(beginline, "-----BEGIN NEW CERTIFICATE REQUEST-----") == 0 &&
         strcmp(endline, "-----END NEW CERTIFICATE REQUEST-----") == 0) ) )
      int_error("Error invalid request format, no BEGIN/END lines");

/* ------------------------------------------------------------------------- *
 * input seems OK, write the request to a temporary mem BIO                  *
 * ------------------------------------------------------------------------- */

   inbio = BIO_new_mem_buf(formreq, -1);

/* ------------------------------------------------------------------------- *
 * Try to read the PEM request with openssl lib functions                    *
 * ------------------------------------------------------------------------- */

   if(! (webrequest = PEM_read_bio_X509_REQ(inbio, NULL, NULL, NULL)))
      int_error("Error cant read request content with PEM function");

   if(! (reqname = X509_REQ_get_subject_name(webrequest)))
      int_error("Error getting subject from cert request");

   if ((pkey=EVP_PKEY_new()) == NULL)
      int_error("Error creating EVP_PKEY structure.");

   if (! (pkey = X509_REQ_get_pubkey(webrequest)))
      int_error("Error getting public key from X509_REQ structure.");

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

/* ------------------------------------------------------------------------- *
 *  Sort out the content and start the html output                           *
 * ------------------------------------------------------------------------- */
   outbio = BIO_new(BIO_s_file());
   BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

   pagehead(title);

   fprintf(cgiOut, "<form action=\"certsign.cgi\" method=\"post\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cert-request\" ");
   fprintf(cgiOut, "value=\"");
   fprintf(cgiOut, formreq);
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
   fprintf(cgiOut, "Expand or Hide Public Key Data</a>");
   /* display the public key data in PEM format here */
   fprintf(cgiOut, "<pre><div class=\"showpem\" id=\"pubkey\" style=\"display: none\">");
   if(!PEM_write_bio_PUBKEY(outbio, pkey))
     BIO_printf(outbio, "Error writing public key data in PEM format");
   fprintf(cgiOut, "</div></pre>\n");
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
   fprintf(cgiOut, "</th>\n");

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
   fprintf(cgiOut, "</td></tr></table></td></tr>\n");

   /* Add extended key usage */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"checkbox\" name=\"extkeyusage\" id=\"exkey_cb\" onclick=\"switchGrey('exkey_cb', 'exkey_td', 'none');\" />");
   fprintf(cgiOut, "</th>\n");

   fprintf(cgiOut, "<td class=type>");
   fprintf(cgiOut, "Extended Key Usage:");
   fprintf(cgiOut, "</td>\n");

   fprintf(cgiOut, "<td id=\"exkey_td\" style=\"background-color: #CFCFCF;\">\n");
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

   /* Set validity by date */
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

   fprintf(cgiOut, "<table width=100%%>\n");

   /* display the request content in PEM format here */
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Show certificate request data in PEM format:");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td class=\"getcert\">");
   fprintf(cgiOut, "<a href=\"javascript:elementHideShow('reqpem');\">\n");
   fprintf(cgiOut, "Expand/Hide Request data in PEM format</a>");
   fprintf(cgiOut, "<div class=\"showpem\" id=\"reqpem\"  style=\"display: none\">");
   fprintf(cgiOut, "<pre>\n");
   PEM_write_bio_X509_REQ(outbio, webrequest);
   fprintf(cgiOut, "</pre>\n");
   fprintf(cgiOut, "</div>\n");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "&nbsp;</th></tr>\n");
   fprintf(cgiOut, "</table>\n");
   pagefoot();
   BIO_free(inbio);
   BIO_free(outbio);
   return(0);
}
