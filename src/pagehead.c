/* -------------------------------------------------------------------------- *
 * file:         pagehead.c                                                   *
 * purpose:      provides a standard page header across all cgi's             *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "webcert.h"

void pagehead(char* title) {

   static char homelink[] = HOMELINK;
 
   cgiHeaderContentType("text/html; charset=UTF-8");
   fprintf(cgiOut, "<html>\n");
   fprintf(cgiOut, "<head>\n");

   fprintf(cgiOut, "<link rel=\"stylesheet\" type=\"text/css\" href=\"../style/style.css\" media=\"screen\" />\n");
   fprintf(cgiOut, "<meta name=\"Title\" content=\"WebCert - %s\" />\n", title);
   fprintf(cgiOut, "<meta name=\"Description\" content=\"WebCert Digital Certificate Management\" />\n");
   fprintf(cgiOut, "<meta name=\"Keywords\" content=\"SSL, HTTPS, TLS, certificate, x509\" />\n");
   fprintf(cgiOut, "<title>WebCert - %s</title>\n", title);
   fprintf(cgiOut, "</head>\n");

   fprintf(cgiOut, "<body>\n");
   fprintf(cgiOut, "<div id=\"wrapper\">\n");
   fprintf(cgiOut, "<div id=\"banner\">\n");
   fprintf(cgiOut, "<h1>WebCert - %s</h1>\n", title);
   fprintf(cgiOut, "<h2>Web-based Digital Certificate Management</h2>\n");
   fprintf(cgiOut, "</div>\n");

   fprintf(cgiOut, "<div id=\"vmenu\">\n");
   fprintf(cgiOut, "<ul>\n");
   fprintf(cgiOut, "<li><a href=\"%s\" class=\"selected\"><span>Home</span></a></li>\n", homelink);
   fprintf(cgiOut, "<li><a href=\"certrequest.cgi\"><span>Paste Requests</span></a></li>\n");
   fprintf(cgiOut, "<li><a href=\"getcert.cgi?cfilename=cacert.pem\"><span>Root CA Cert</span></a></li>\n");
   fprintf(cgiOut, "<li><a href=\"certstore.cgi\"><span>List Certs</span></a></li>\n");
   fprintf(cgiOut, "<li><a href=\"certsearch.cgi\"><span>Search Certs</span></a></li>\n");
   fprintf(cgiOut, "<li><a href=\"certvalidate.cgi\"><span>Verify Certs</span></a></li>\n");
   fprintf(cgiOut, "<li><a href=\"help.cgi\"><span>Help</span></a></li>\n");
   fprintf(cgiOut, "<li><a href=\"capolicy.cgi\"><span>About</span></a></li>\n");
   fprintf(cgiOut, "</ul>\n");
   fprintf(cgiOut, "</div>\n");

   fprintf(cgiOut, "<div id=\"content\">\n");
}
