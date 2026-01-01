/* -------------------------------------------------------------------------- *
 * file:         pagehead.c                                                   *
 * purpose:      provides a standard page header across all cgi's             *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "webcert.h"

void pagehead(char* title) {
   int ret;
   FILE *fp;

   cgiHeaderContentType("text/html; charset=UTF-8");
   fprintf(cgiOut, "<!DOCTYPE html>");
   fprintf(cgiOut, "<html>\n");
   fprintf(cgiOut, "<head>\n");

   /* ---------------------------------------------------------- *
    * Replicate same content as site-headermeta.htm for dynamic  *
    * page title generation.                                     *
    * -----------------------------------------------------------*/
   fprintf(cgiOut, "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n");
   fprintf(cgiOut, "<link rel=\"stylesheet\" type=\"text/css\" href=\"/style/style.css\" />\n");
   fprintf(cgiOut, "<meta name=\"Title\" content=\"WebCert - %s\" />\n", title);
   fprintf(cgiOut, "<meta name=\"Description\" content=\"WebCert Digital Certificate Management\" />\n");
   fprintf(cgiOut, "<meta name=\"Keywords\" content=\"SSL, HTTPS, TLS, certificate, x509\" />\n");
   fprintf(cgiOut, "<title>WebCert - %s</title>\n", title);
   fprintf(cgiOut, "<script src=\"/webcert.js\" type=\"text/javascript\"></script>\n");
   fprintf(cgiOut, "</head>\n");

   fprintf(cgiOut, "<body>\n");
   fprintf(cgiOut, "<div id=\"banner\">\n");
   fprintf(cgiOut, "<h1>WebCert - %s</h1>\n", title);
   fprintf(cgiOut, "<h2>Web-based Digital Certificate Management</h2>\n");
   fprintf(cgiOut, "</div>\n");

   /* ---------------------------------------------------------- *
    * Read content of site-navigation.htm to create header links *
    * -----------------------------------------------------------*/
   if ((fp = fopen(HEADER_VMENU, "r"))) {
      for(;;) {
         ret = getc(fp);
         if(ret == EOF) break;
         fprintf(cgiOut, "%c", ret);
      }
   }

   fprintf(cgiOut, "<div id=\"wrapper\">\n");
   fprintf(cgiOut, "<div id=\"content\">\n");
}
