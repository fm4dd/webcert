/* -------------------------------------------------------------------------- *
 * file:         certrequest.c                                                *
 * purpose:      cut & paste form for certificate request                     *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "webcert.h"

int cgiMain() {

   static char title[] = "Paste a Certificate Request";

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

   fprintf(cgiOut, "<form action=\"certverify.cgi\" method=\"post\">\n");

   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "Please paste your certificate request into the ");
   fprintf(cgiOut, "field below:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"getcert\">");
   fprintf(cgiOut, "<textarea name=\"csr-data\" cols=\"65\" rows=\"25\">");
   fprintf(cgiOut, "</textarea>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Verify\" />");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "</form>");
   fprintf(cgiOut, "<p></p>\n");
   fprintf(cgiOut, "<form enctype=\"multipart/form-data\" action=\"certverify.cgi\" method=\"post\">\n");

   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "Alternatively, you can upload your certificate request file");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td class=\"type250\">");
   fprintf(cgiOut, "Upload Your CSR file (PEM format)");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"file\" name=\"csr-file\" value=\"\" style=\"background:#ccc; width: 100%%\" />");
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=\"2\">");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Upload\" />");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "</form>");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot();
   return(0);
}
