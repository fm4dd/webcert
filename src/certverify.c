/* -------------------------------------------------------------------------- *
 * file:	certverify.cgi                                                *
 * purpose:	verify the certificate entries before signing                 *
 * compile:     gcc -I/usr/local/ssl/include -L/usr/local/ssl/lib             *
 * certverify.c -o certverify.cgi -lcgic -lssl -lcrypto                       *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <openssl/pem.h>
#include "webcert.h"

void File()
{
  cgiFilePtr file;
  char name[1024];
  char contentType[1024];
  char buffer[1024];
  int size;
  int got;
        fprintf(cgiOut, "The filename submitted was: ");
        cgiHtmlEscape(name);
        fprintf(cgiOut, "<p>\n");
        cgiFormFileSize("file", &size);
        fprintf(cgiOut, "The file size was: %d bytes<p>\n", size);
        cgiFormFileContentType("file", contentType, sizeof(contentType));
        fprintf(cgiOut, "The alleged content type of the file was: ");
        cgiHtmlEscape(contentType);
        fprintf(cgiOut, "<p>\n");
  fprintf(cgiOut, "Of course, this is only the claim the browser "
    "made when uploading the file. Much like the filename, "
    "it cannot be trusted.<p>\n");
  fprintf(cgiOut, "The file's contents are shown here:<p>\n");
  if (cgiFormFileOpen("file", &file) != cgiFormSuccess) {
    fprintf(cgiOut, "Could not open the file.<p>\n");
    return;
  }
  fprintf(cgiOut, "<pre>\n");
  while (cgiFormFileRead(file, buffer, sizeof(buffer), &got) ==
    cgiFormSuccess)
  {
    cgiHtmlEscapeData(buffer, got);
  }
  fprintf(cgiOut, "</pre>\n");
  cgiFormFileClose(file);
}

int cgiMain() {

   BIO 			*inbio;
   X509_REQ 		*webrequest = NULL;
   X509_NAME 		*reqname = NULL;
   X509_NAME_ENTRY 	*e;
   int 			i;
   char 		buf[80] = "";
   char 		formreq[REQLEN] = "";
   char 		reqtest[REQLEN] = "";
   char 		beginline[81]   = "";
   char 		endline[81]     = "";
   static char 		title[] = "Verify Request";

   int                  filesize = 0;
   cgiFilePtr		file;

/* ------------------------------------------------------------------------- *
 * check if a certificate was handed to certsign.cgi                         *
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

/* ------------------------------------------------------------------------- *
 *  and sort out the content plus start the html output                      *
 * ------------------------------------------------------------------------- */

   pagehead(title);

   fprintf(cgiOut, "<form action=\"certsign.cgi\" method=\"get\">");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cert-request\" ");
   fprintf(cgiOut, "value=\"");
   fprintf(cgiOut, formreq);
   fprintf(cgiOut, "\">\n");
   fprintf(cgiOut, "<table width=100%%>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Subject Data of this Certificate Request:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");

   for (i = 0; i < X509_NAME_entry_count(reqname); i++) {
      e = X509_NAME_get_entry(reqname, i);
      OBJ_obj2txt(buf, 80, e->object, 0);

      fprintf(cgiOut, "<tr>");
      fprintf(cgiOut, "<td align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
      fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
      fprintf(cgiOut, "%s%s", buf ,"</td>");
      fprintf(cgiOut, "</font>");
      fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
      fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
      fprintf(cgiOut, "%s", e->value->data);
      fprintf(cgiOut, "</font>");
      fprintf(cgiOut, "</td>");
      fprintf(cgiOut, "</tr>");
   }

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");

   /* Certificate Settings Header */
   fprintf(cgiOut, "Define Certificate Details:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   /* Certificate Settings start here */
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td  rowspan=5 align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "Set Key Usage:</font></td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=sv checked>");
   fprintf(cgiOut, " SSL Server</font></td></tr><tr>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=cl>");
   fprintf(cgiOut, " SSL Client</font></td></tr><tr>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=em>");
   fprintf(cgiOut, " E-Mail Encryption ");
   fprintf(cgiOut, "<input type=text size=26 name=\"ename\">");
   fprintf(cgiOut, " Address</font></td></tr><tr>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=os>");
   fprintf(cgiOut, " Object Signing</font></td></tr><tr>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "<input type=radio name=\"type\" value=ca>");
   fprintf(cgiOut, " CA Certificate</font></td></tr>");

   /* extended key usage information */
   fprintf(cgiOut, "<tr><td align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "Set Extended Key Usage:");
   fprintf(cgiOut, "</font></td>");

   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
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
   fprintf(cgiOut, "</font></td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr><td align=\"left\" width=\"200\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "Set Expiration Date:");
   fprintf(cgiOut, "</font></td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\">");
   fprintf(cgiOut, "<input type=text name=\"edate\" size=4 value=%d>", DAYS_VALID);
   fprintf(cgiOut, " Days until Expiration");
   fprintf(cgiOut, "</font></td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr><th colspan=\"2\">");
   fprintf(cgiOut, "<input type=\"button\" name=\"Forget it!\" value=");
   fprintf(cgiOut, "\"  Go Back  \" onClick=");
   fprintf(cgiOut, "\"self.location.href='certrequest.cgi'\">&nbsp;");
   fprintf(cgiOut, "&nbsp;<input type=\"submit\" value=\"Sign Request\">");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "</form>");
   pagefoot();
   BIO_free(inbio);
   return(0);
}
