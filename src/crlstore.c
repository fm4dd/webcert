/* -------------------------------------------------------------------------- *
 * file:         crlstore.c                                                   *
 * purpose:      display the list of revoked certificates                     *
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

int cgiMain() {

  static char      title[]           = "List of revoked Certificates";
         char      sorting[16]       = "desc";
         int       pagenumber        = 1;
         int       certcounter       = 0;
         int       tempcounter       = 0;
         int       pagecounter       = 0;
	 div_t     disp_calc;
         BIO       *outbio           = NULL;
         X509_CRL *crl = NULL;


/* ---------------------------------------------------------- *
 * Get the number of revoked certs                            *
 * ---------------------------------------------------------- */
  crl = cgi_load_crlfile(CRLFILE);
  STACK_OF(X509_REVOKED) *rev = X509_CRL_get_REVOKED(crl);
  certcounter = sk_X509_REVOKED_num(rev);

/* ----------------------------------------------------------- *
 * calculate how many pages we get with MAXCERTDISPLAY         *
 * ------------------------------------------------------------*/
  if(certcounter<=MAXCERTDISPLAY) pagecounter = 1;
  else {
    disp_calc = div(certcounter, MAXCERTDISPLAY);
    /* if the count of certs divided by MAXCERTDISPLAY has no remainder */
    if(disp_calc.rem == 0) pagecounter = disp_calc.quot;
    /* with a remainder, we must prepare an extra page for the rest */
    else pagecounter = disp_calc.quot +1;
  }

/* ---------------------------------------------------------- *
 * Check if CGI was called with a pagenumber and sort request *
 * ---------------------------------------------------------- */
  if(cgiFormInteger("page", &pagenumber, 1) == cgiFormSuccess)
    if(pagenumber > pagecounter || pagenumber <=0)
      int_error("Error: Page does not exist.");

  if(cgiFormString("sort", sorting, sizeof(sorting)) != cgiFormSuccess)
      strncpy(sorting, "desc", sizeof(sorting));

/* ---------------------------------------------------------- *
 * start the html output                                      *
 * ---------------------------------------------------------- */
  outbio = BIO_new(BIO_s_file());
  BIO_set_fp(outbio, cgiOut, BIO_NOCLOSE);

  pagehead(title);

  //debugging only:
  //printf("Cert sort order: %s\n", sorting);
  //printf("Number of certs: %d\n", certcounter);
  //printf("Num tempcounter: %d\n", tempcounter);
  //printf("Number of pages: %d\n", pagecounter);
  //printf("Selected page #: %d\n", pagenumber);
  //printf("Div Quotient: %d\n", disp_calc.quot);
  //printf("Div Remainder: %d\n", disp_calc.rem);
  //fprintf(cgiOut, "</BODY></HTML>\n");
  //exit(0);

/* ---------------------------------------------------------- *
 * start the form output                                      *
 * ---------------------------------------------------------- */

  display_crl_list(crl, MAXCERTDISPLAY, sorting, pagenumber);

  fprintf(cgiOut, "<p></p>\n");

  fprintf(cgiOut, "<table>\n");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>\n");
  fprintf(cgiOut, "<form action=\"crlstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"desc\" />\n");
  fprintf(cgiOut, "<input type=\"submit\" name=\"sort\"");
  fprintf(cgiOut, " value=\"Latest Certs first\" />\n");
  fprintf(cgiOut, "</form>\n");
  fprintf(cgiOut, "</th>\n");

  fprintf(cgiOut, "<th>\n");
  fprintf(cgiOut, "<form action=\"crlstore.cgi\" method=\"post\">\n");
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

  if(pagenumber == 1) {
    fprintf(cgiOut, "<th width=\"78px\">\n");
    fprintf(cgiOut, "Newest Page");
    fprintf(cgiOut, "</th>\n");
  }
  else {
    // goto page 1
    fprintf(cgiOut, "<th width=\"5\">\n");
    fprintf(cgiOut, "<form action=\"crlstore.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<input type=\"submit\" value=\"&lt;&lt;\" />\n");
    fprintf(cgiOut, "</form>\n");
    fprintf(cgiOut, "</th>\n");
  
    // goto page before
    fprintf(cgiOut, "<th width=\"5\">\n");
    fprintf(cgiOut, "<form action=\"crlstore.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", certcounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
    fprintf(cgiOut, "value=\"%s\" />\n", sorting);
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
  }

  if(pagenumber == pagecounter) {
    fprintf(cgiOut, "<th width=\"78px\">\n");
    fprintf(cgiOut, "Oldest Page");
    fprintf(cgiOut, "</th>\n");
  }
  else {
    // goto page after
    fprintf(cgiOut, "<th width=\"5\">\n");
    fprintf(cgiOut, "<form action=\"crlstore.cgi\" method=\"post\">\n");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", certcounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
    fprintf(cgiOut, "value=\"%s\" />\n", sorting);
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
    fprintf(cgiOut, "<form action=\"crlstore.cgi\" method=\"post\">");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", certcounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
    fprintf(cgiOut, "value=\"%d\" />\n", pagecounter);
    fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
    fprintf(cgiOut, "value=\"%s\" />\n", sorting);
    fprintf(cgiOut, "<input type=\"submit\" value=\"&gt;&gt;\" />\n");
    fprintf(cgiOut, "</form>\n");
    fprintf(cgiOut, "</th>\n");
  }
  // goto page number
  fprintf(cgiOut, "<th width=\"120\">\n");
  fprintf(cgiOut, "<form class=\"setpage\" action=\"crlstore.cgi\" method=\"post\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"certcounter\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%d", certcounter);
  fprintf(cgiOut, "\" />\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"pagecounter\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%d", pagecounter);
  fprintf(cgiOut, "\" />\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"%s\" />\n", sorting);
  fprintf(cgiOut, "<input class=\"goto\" type=\"submit\" value=\"Goto\" />\n");
  fprintf(cgiOut, "&nbsp; &nbsp;");
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

  BIO_free(outbio);
  return(0);
}
