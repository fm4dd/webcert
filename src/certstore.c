/* -------------------------------------------------------------------------- *
 * file:         certstore.c                                                  *
 * purpose:      display the list of signed certificates                      *
 * -------------------------------------------------------------------------- */

/* defines needed for strptime() function */
#define _XOPEN_SOURCE
#define __USE_XOPEN
#define __USE_GNU
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "webcert.h"

int hexsort(const struct dirent **test1, const struct dirent **test2) {
  char *endptr;
  return (strtol((*test1)->d_name, &endptr, 16)
        - strtol((*test2)->d_name, &endptr, 16));
}

int file_select(const struct dirent *entry) {

  /* check for "." and ".." directory entries */
  if(entry->d_name[0]=='.') return 0;

  /* Check for <id>.pem file name extensions */
  if(strstr(entry->d_name, ".pem") != NULL) return 1;
  else return 0;
}

int cgiMain() {

  static char      title[]           = "List of existing Certificates";
         char      sorting[16]       = "desc";
         char      certfilestr[225]  = "";
         FILE      *certfile         = NULL;
         BIO       *membio           = NULL;
         BIO       *outbio           = NULL;
         char      membio_buf[128]   = "";
         X509      *cert             = NULL;
         X509_NAME *certsubject      = NULL;
         ASN1_TIME *start_date       = NULL;
         ASN1_TIME *expiration_date  = NULL;
  struct tm        start_tm;
  struct tm        expiration_tm;
         time_t    now               = time(NULL);
         time_t    start             = time(NULL);
         time_t    expiration        = time(NULL);
         double    available_secs    = 0;
         double    remaining_secs    = 0;
  struct dirent    **certstore_files = NULL;
         int       pagenumber        = 1;
         int       certcounter       = 0;
         int       tempcounter       = 0;
         int       pagecounter       = 0;
         int       dispcounter       = 0;
         int       dispmaxlines      = 0;
         int       certvalidity      = 0;
         div_t     disp_calc;
         div_t     oddline_calc;
         double    percent           = 0;

         cert                       = X509_new();
         certsubject                = X509_NAME_new();

/* -------------------------------------------------------------------------- *
 * Get the list of .pem files from the cert directory                         *
 * ---------------------------------------------------------------------------*/
  certcounter = scandir(CACERTSTORE, &certstore_files, file_select, hexsort);
  if(certcounter<=0) int_error("Error: No certificate files found.");

/* -------------------------------------------------------------------------- *
 * calculate how many pages we get with MAXCERTDISPLAY                         *
 * ---------------------------------------------------------------------------*/

  if(certcounter<=MAXCERTDISPLAY) pagecounter = 1;
  else {
    disp_calc = div(certcounter, MAXCERTDISPLAY);
    /* if the count of certs divided by MAXCERTDISPLAY has no remainder */
    if(disp_calc.rem == 0) pagecounter = disp_calc.quot;
    /* with a remainder, we must prepare an extra page for the rest */
    else pagecounter = disp_calc.quot +1;
  }

/* -------------------------------------------------------------------------- *
 * Check if we have been subsequently called with a pagenumber & sort request *
 * ---------------------------------------------------------------------------*/

  if(cgiFormInteger("page", &pagenumber, 1) == cgiFormSuccess)
    if(pagenumber > pagecounter || pagenumber <=0)
      int_error("Error: Page does not exist.");

  if(cgiFormString("sort", sorting, sizeof(sorting)) != cgiFormSuccess)
      strncpy(sorting, "desc", sizeof(sorting));

/* -------------------------------------------------------------------------- *
 * now we know how many certs we have in total and we can build the page(s).  *
 * For every MAXCERTDISPLAY certs we start a new page and cycle through by    *
 * calling ourself with the requested certs in range.                         *
 * ---------------------------------------------------------------------------*/

  if(strcmp(sorting, "asc") == 0) {

    if(certcounter <= MAXCERTDISPLAY) {
       dispmaxlines = certcounter;
       tempcounter = 0;
    }
    else
      if(pagenumber == pagecounter &&
             ( pagecounter * MAXCERTDISPLAY) - certcounter != 0) {

        tempcounter = (pagecounter * MAXCERTDISPLAY) - MAXCERTDISPLAY;
        dispmaxlines = certcounter - ((pagecounter-1) * MAXCERTDISPLAY);
      }
      else {

        tempcounter = (pagenumber * MAXCERTDISPLAY) - MAXCERTDISPLAY;
        dispmaxlines = MAXCERTDISPLAY;
      }
  }

  if(strcmp(sorting, "desc") == 0) {

    if(certcounter <= MAXCERTDISPLAY) {
       dispmaxlines = certcounter;
       tempcounter = certcounter;
    }
    else
      if(pagenumber == pagecounter &&
             ( pagecounter * MAXCERTDISPLAY) - certcounter != 0) {

        tempcounter = certcounter - ((pagecounter-1) * MAXCERTDISPLAY);
        dispmaxlines = certcounter - ((pagecounter-1) * MAXCERTDISPLAY);
      }
      else {

       tempcounter = certcounter - (pagenumber*MAXCERTDISPLAY) + MAXCERTDISPLAY;
       dispmaxlines = MAXCERTDISPLAY;
      }
  }

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

  outbio = BIO_new(BIO_s_file());
  BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

  pagehead(title);

  //debugging only:
  //printf("Number of certs: %d\n", certcounter);
  //printf("Num tempcounter: %d\n", tempcounter);
  //printf("Number of pages: %d\n", pagecounter);
  //printf("Div Quotient: %d\n", disp_calc.quot);
  //printf("Div Remainder: %d\n", disp_calc.rem);
  //fprintf(cgiOut, "</BODY></HTML>\n");
  //exit(0);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th width=\"20\">");
   fprintf(cgiOut, "#");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "<th width=\"495\">");
   fprintf(cgiOut, "Certificate Subject Information");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "<th colspan=\"2\" width=\"60\">");
   fprintf(cgiOut, "Expiry");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "<th width=\"65\">");
   fprintf(cgiOut, "Action");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");

  for(dispcounter=0; dispcounter < dispmaxlines; dispcounter++) {

    /* zero certificate values and flags */
    certvalidity = 0;
    percent = 0;
    available_secs = 0;
    remaining_secs = 0;
    cert = X509_new();
    certsubject = X509_NAME_new();

    if(strcmp(sorting, "desc") == 0) tempcounter--;

    snprintf(certfilestr, sizeof(certfilestr), "%s/%s",
                           CACERTSTORE, certstore_files[tempcounter]->d_name);

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th rowspan=\"2\">");
    fprintf(cgiOut, "%d", tempcounter+1);
    fprintf(cgiOut, "</th>\n");

    oddline_calc = div(tempcounter+1, 2);
    if(oddline_calc.rem)
      fprintf(cgiOut, "<td rowspan=\"2\" class=\"odd\">");
    else
      fprintf(cgiOut, "<td rowspan=\"2\" class=\"even\">");

    if ( (certfile = fopen(certfilestr, "r")) != NULL) {
      PEM_read_X509(certfile, &cert, NULL, NULL);
      certsubject = X509_get_subject_name(cert);

      /* display the subject data, use the UTF-8 flag to show  *
       * Japanese Kanji, also needs the separator flag to work */
      X509_NAME_print_ex_fp(cgiOut, certsubject, 0,
         ASN1_STRFLGS_UTF8_CONVERT|XN_FLAG_SEP_CPLUS_SPC);

      /* store certificate start date for later eval */
      start_date = X509_get_notBefore(cert);

      /* store certificate expiration date for later eval */
      expiration_date = X509_get_notAfter(cert);

      /* check the start and end dates in the cert */
      if (X509_cmp_current_time (X509_get_notBefore (cert)) >= 0)
        /* flag the certificate as not valid yet */
        certvalidity = 0;
      else
      if (X509_cmp_current_time (X509_get_notAfter (cert)) <= 0)
        /* flag the certificate as expired */
        certvalidity = 0;
      else 
        /* flag the certificate is still valid */
        certvalidity = 1;

      fclose(certfile);
    }
    else 
       fprintf(cgiOut, "Error: Can't open certificate file %s for reading.",
                                                                 certfilestr);
    fprintf(cgiOut, "</td>\n");

    if(certvalidity == 0) {

      /* expiration bar display column */
      fprintf(cgiOut, "<th rowspan=\"2\">\n");
      fprintf(cgiOut, "<table class=\"led\">\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "</table>\n");
      fprintf(cgiOut, "</th>\n");

      /* remaining days before expiration column */
      fprintf(cgiOut, "<th class=\"exnok\" rowspan=\"2\">\n");
      fprintf(cgiOut, "Inval<br />Expd");
      fprintf(cgiOut, "</th>\n");
    }

    if(certvalidity == 1) {

      /* ------ START get the certificate lifetime in seconds ------ */
      /* copy the start date into a string */
      membio = BIO_new(BIO_s_mem());
      ASN1_TIME_print(membio, start_date);
      BIO_gets(membio, membio_buf, sizeof(membio_buf));
      BIO_free(membio);

      /* parse the start date string into a time struct */
      memset (&start_tm, '\0', sizeof(start_tm));
      strptime(membio_buf, "%h %d %T %Y %z", &start_tm);
      start = mktime(&start_tm);

      /* ------ START get the certificate remaining time in seconds ------ */
      /* copy the expiration date into a string */
      membio = BIO_new(BIO_s_mem());
      ASN1_TIME_print(membio, expiration_date);
      BIO_gets(membio, membio_buf, sizeof(membio_buf));
      BIO_free(membio);
  
      /* parse the expiration date string into a time struct */
      memset (&expiration_tm, '\0', sizeof(expiration_tm));
      strptime(membio_buf, "%h %d %T %Y %z", &expiration_tm);
  
      /* get the current time */
      now = time(NULL);
      expiration = mktime(&expiration_tm);
  
      /* get the time difference between expiration time and current time */
      remaining_secs = difftime(expiration, now);
      /* ------ END get the certificate remaining time in seconds ------ */

      /* get the time difference between start and expiration time */
      available_secs = difftime(expiration, start);
      /* ------ END get the certificate lifetime in seconds ------ */
  
      /* ------ START calculate percentage of lifetime left ------ */
      /* remaining_secs *100                                       */
      /* ------------------- = X, rounded down with floor()        */
      /* available_secs                                            */
      percent = floor((remaining_secs*100)/available_secs);
      /* ------ END calculate percentage of lifetime left   ------ */
  
      /* expiration bar display column */
      fprintf(cgiOut, "<th rowspan=\"2\">\n");
      fprintf(cgiOut, "<table class=\"led\">\n");
      if (percent >= 90) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#00FF00\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 80) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#00FF33\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 70) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#99FF33\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 60) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#FFFF00\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 50) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#FFCC00\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 40) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#FF9900\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 30) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#FF6600\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 20) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#FF3300\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      if (percent >= 10) fprintf(cgiOut, "  <tr><td class=\"led\" bgcolor=\"#FF0000\"></td></tr>\n");
      else fprintf(cgiOut, "  <tr><td class=\"led-off\"></td></tr>\n");
      fprintf(cgiOut, "</table>\n");
      fprintf(cgiOut, "</th>\n");
  
      /* remaining days before expiration column */
      //fprintf(cgiOut, membio_buf);
      if (percent < 10) fprintf(cgiOut, "<th class=\"exnok\" rowspan=\"2\">\n");
      else fprintf(cgiOut, "<th class=\"exok\" rowspan=\"2\">\n");
      if(floor(remaining_secs/63072000) > 0) fprintf(cgiOut, "%.f<br />years", remaining_secs/31536000);
      else if(floor(remaining_secs/86400) > 0 ) fprintf(cgiOut, "%.f<br />days", remaining_secs/86400);
      else if(floor(remaining_secs/3600) > 0 ) fprintf(cgiOut, "%.f<br />hours", remaining_secs/3600);
      else if(floor(remaining_secs/60) > 0 ) fprintf(cgiOut, "%.f<br />mins", remaining_secs/60);
      else fprintf(cgiOut, "%.f<br />secs", remaining_secs);
      fprintf(cgiOut, "</th>\n");
    }

    /* action column */
    fprintf(cgiOut, "<th>");
    fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
    fprintf(cgiOut, "value=\"%s\" />\n", certstore_files[tempcounter]->d_name);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"text\" />\n");
    fprintf(cgiOut, "<input class=\"getcert\" type=\"submit\" value=\"Detail\" />\n");
    fprintf(cgiOut, "</form>\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
    fprintf(cgiOut, "value=\"%s\" />\n", certstore_files[tempcounter]->d_name);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"text\" />\n");
    fprintf(cgiOut, "<input class=\"getcert\" type=\"submit\" value=\"Renew\" />\n");
    fprintf(cgiOut, "</form>\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    if(strcmp(sorting, "asc") == 0) tempcounter++;
  }

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"5\">");
  fprintf(cgiOut, "Total # of certs: %d | ", certcounter);
  fprintf(cgiOut, "Page %d of %d", pagenumber, pagecounter);
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");

  fprintf(cgiOut, "<p></p>\n");

  fprintf(cgiOut, "<table>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>\n");
  fprintf(cgiOut, "<form action=\"certstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"desc\" />\n");
  fprintf(cgiOut, "<input type=\"submit\" name=\"sort\"");
  fprintf(cgiOut, " value=\"Latest Certs first\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<th>\n");
  fprintf(cgiOut, "<form action=\"certstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"asc\" />\n");
  fprintf(cgiOut, "<input type=\"submit\" name=\"sort\"");
  fprintf(cgiOut, " value=\"Oldest Certs first\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  // filler 1
  fprintf(cgiOut, "<th width=\"15\">");
  fprintf(cgiOut, "&nbsp;");
  fprintf(cgiOut, "</th>\n");

  // goto page 1
  fprintf(cgiOut, "<th width=\"5\">\n");
  fprintf(cgiOut, "<form action=\"certstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"submit\" value=\"&lt;&lt;\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  // goto page before
  fprintf(cgiOut, "<th width=\"5\">\n");
  fprintf(cgiOut, "<form action=\"certstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", certcounter);
  fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
  fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
  fprintf(cgiOut, "value=\"");
  tempcounter = 0;
  if(pagenumber > 1) tempcounter = pagenumber - 1;
  else tempcounter = 1;
  fprintf(cgiOut, "%d", tempcounter);
  fprintf(cgiOut, "\" />\n");
  fprintf(cgiOut, "<input type=\"submit\" value=\"&lt; 1\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  // goto page after
  fprintf(cgiOut, "<th width=\"5\">\n");
  fprintf(cgiOut, "<form action=\"certstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", certcounter);
  fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
  fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
  fprintf(cgiOut, "value=\"");
  tempcounter = 0;
  if(pagecounter > pagenumber) tempcounter = pagenumber + 1;
  else tempcounter = pagecounter;
  fprintf(cgiOut, "%d", tempcounter);
  fprintf(cgiOut, "\" />\n");
  fprintf(cgiOut, "<input type=\"submit\" value=\"1 &gt;\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  // goto last page
  fprintf(cgiOut, "<th width=\"5\">\n");
  fprintf(cgiOut, "<form action=\"certstore.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", certcounter);
  fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
  fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
  fprintf(cgiOut, "<input type=\"submit\" value=\"&gt;&gt;\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  // goto page number
  fprintf(cgiOut, "<th width=\"120\">\n");
  fprintf(cgiOut, "<form class=\"setpage\" action=\"certstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%d", certcounter);
  fprintf(cgiOut, "\" />\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%d", pagecounter);
  fprintf(cgiOut, "\" />\n");
  fprintf(cgiOut, "<input class=\"goto\" type=\"submit\" value=\"Goto\" />\n");
  fprintf(cgiOut, "<input class=\"page\" type=\"text\" name=\"page\" ");
  fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");

/* ---------------------------------------------------------------------------*
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

  pagefoot();
  return(0);
}
