/* -------------------------------------------------------------------------- *
 * file:	 handle_error.c                                               *
 * purpose:      provides a standard error page for all cgi's                 *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <openssl/err.h>
#include "webcert.h"

void handle_error(const char *file, int lineno, const char *msg) {
   void ERR_load_crypto_strings(void);
   void ERR_load_BIO_strings(void);
   void ERR_free_strings(void);

   static char title[] = "System Error Information";

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/
   pagehead(title);

   fprintf(cgiOut, "<h3>%s Error</h3>\n", SW_VERSION);
   fprintf(cgiOut, "<hr />");
   fprintf(cgiOut, "<ul><li>file: %s line: %d error: %s</li></ul>\n", file, lineno, msg);

   fprintf(cgiOut, "<h3>Additional Information</h3>\n");
   fprintf(cgiOut, "<hr />");
   fprintf(cgiOut, "<p><pre>");
   ERR_print_errors_fp(cgiOut);
   fprintf(cgiOut, "</pre></p>");

   fprintf(cgiOut, "<p>");
   fprintf(cgiOut, "For most common errors, please see section 10. under <a href=\"help.cgi\">Help</a>.\n");
   fprintf(cgiOut, "If the problem persists, please contact me at <a href=\"mailto:%s\">%s</a>\n", CONTACT_EMAIL, CONTACT_EMAIL);
   fprintf(cgiOut, "with the info above and include the cert or request.");
   fprintf(cgiOut, "</p>");
   pagefoot();
   exit(-1);
}
