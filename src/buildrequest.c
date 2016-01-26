/* -------------------------------------------------------------------------- *
 * file:         buildrequest.c                                               *
 * purpose:      use a web form to build a certificate request from scratch   *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "webcert.h"

int cgiMain() {
   static char title[] = "Build a Certificate Request";

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/
   pagehead(title);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

   fprintf(cgiOut, "<form action=\"genrequest.cgi\" method=\"post\" accept-charset=\"utf-8\">");

   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">Certificate Structure Data</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">C</th>");
   fprintf(cgiOut, "<td class=\"type\">Country</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"c\" size=\"20\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">US, GB, DE, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">ST</th>");
   fprintf(cgiOut, "<td class=\"type\">State or Province</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"st\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "CA, NV, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">L</th>");
   fprintf(cgiOut, "<td class=\"type\">Location, City</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"l\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Rocklin, Los Angeles, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">O</th>");
   fprintf(cgiOut, "<td class=\"type\">Organisation, Company</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"o\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Frank4DD, ACME Corp, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">OU</th>");
   fprintf(cgiOut, "<td class=\"type\">Dept or Subdivision</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"ou\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Support, Sales, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">eA</th>");
   fprintf(cgiOut, "<td class=\"type\">E-Mail Address</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"email\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "you@somewhere.com</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">CN</th>");
   fprintf(cgiOut, "<td class=\"type\">System Name *</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"cn\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "i.e. www.fm4dd.com</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr><th colspan=\"4\">&nbsp;</th></tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "* Mandatory field CN: Can be set with a DNS name, IP address, serial number, or any other identifier.\n");
   fprintf(cgiOut, "<p></p>\n");

   keycreate_input();
   fprintf(cgiOut, "<p></p>\n");

   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">");
   fprintf(cgiOut, "Optional: Request Certificate Extension Data");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th rowspan=\"4\">SAN</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "<select name=\"typesan1\">\n");
   fprintf(cgiOut, "<option value=\"DNS\" selected=\"selected\">DNS Name 1</option>\n");
   fprintf(cgiOut, "<option value=\"IP\">IP Address 1</option>\n");
   fprintf(cgiOut, "<option value=\"URI\">URI 1</option>\n");
   fprintf(cgiOut, "<option value=\"RID\">Registered ID 1</option>\n");
   fprintf(cgiOut, "</select></td>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"datasan1\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Subject Alternative Name 1</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "<select name=\"typesan2\">\n");
   fprintf(cgiOut, "<option value=\"DNS\" selected=\"selected\">DNS Name 2</option>\n");
   fprintf(cgiOut, "<option value=\"IP\">IP Address 2</option>\n");
   fprintf(cgiOut, "<option value=\"URI\">URI 2</option>\n");
   fprintf(cgiOut, "<option value=\"RID\">Registered ID 2</option>\n");
   fprintf(cgiOut, "</select></td>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"datasan2\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Subject Alternative Name 2</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "<select name=\"typesan3\">\n");
   fprintf(cgiOut, "<option value=\"DNS\" selected=\"selected\">DNS Name 3</option>\n");
   fprintf(cgiOut, "<option value=\"IP\">IP Address 3</option>\n");
   fprintf(cgiOut, "<option value=\"URI\">URI 3</option>\n");
   fprintf(cgiOut, "<option value=\"RID\">Registered ID 3</option>\n");
   fprintf(cgiOut, "</select></td>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"datasan3\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Subject Alternative Name 3</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "<select name=\"typesan4\">\n");
   fprintf(cgiOut, "<option value=\"DNS\" selected=\"selected\">DNS Name 4</option>\n");
   fprintf(cgiOut, "<option value=\"IP\">IP Address 4</option>\n");
   fprintf(cgiOut, "<option value=\"URI\">URI 4</option>\n");
   fprintf(cgiOut, "<option value=\"RID\">Registered ID 4</option>\n");
   fprintf(cgiOut, "</select></td>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"datasan4\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Subject Alternative Name 4</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">");
   fprintf(cgiOut, "Optional: For E-Mail Encryption (S/MIME) certificates, set the User Name:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">GN</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Given Name</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"gn\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "First Name, i.e. John, Paul</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\">SN</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Surname</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"sn\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Last Name, i.e. Doe, Miller</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">&nbsp;</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "<p></p>\n");

   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th class=\"cnt\"><input type=\"submit\" value=\"Generate\" /></th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "</form>");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot();
   return(0);
}
