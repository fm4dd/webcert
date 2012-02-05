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

   fprintf(cgiOut, "<form action=\"genrequest.cgi\" method=\"post\">");
   fprintf(cgiOut, "<table width=100%%>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "To generate a certificate request, please fill out ");
   fprintf(cgiOut, "the fields below:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "C</th>");
   fprintf(cgiOut, "<td align=\"left\" width=\"100\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<b>Country</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"c\" size=20 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "US, GB, DE, etc</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "ST</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<b>State or Province</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"st\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "CA, NV, etc</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "L</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<b>Location, City</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"l\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "Rocklin, Los Angeles, etc</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "O</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<b>Organisation, Company</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"o\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "Frank4DD, ACME Corp, etc</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "OU</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<b>Dept or Subdivision</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"ou\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "Support, Sales, etc</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "eA</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>E-Mail Address</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"email\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "you@somewhere.com</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "CN</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<b>System Name</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"cn0\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "i.e. www.frank4dd.com</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "CN</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>System IP Address</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"cn1\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "i.e. 192.168.11.101</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "CN</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>Other Common Name</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"cn2\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "i.e. S/N 123-456789ABCD</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "For E-Mail Encryption (S/MIME) certificates, set the User Name:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "GN</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>Given Name</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"gn\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "First Name, i.e. John, Paul</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "SN</th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>Surname</b></td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=\"text\" name=\"sn\" size=40 value=>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "Last Name, i.e. Doe, Miller</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "Select the options for the public/private key pair:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=radio checked name=keytype value=rsa></th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>Generate RSA key pair</b></td>");

   fprintf(cgiOut, "<td align=\"center\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<select name=\"rsastrength\">");
   fprintf(cgiOut, "<option value=\"512\">Key Strength: 512 bit (Poor)</option>");
   fprintf(cgiOut, "<option value=\"1024\" selected>");
   fprintf(cgiOut, "Key Strength: 1024 bit (Good)</option>");
   fprintf(cgiOut, "<option value=\"2048\">Key Strength: 2048 bit (Better)</option>");
   fprintf(cgiOut, "<option value=\"4096\">Key Strength: 4096 bit (Best)");
   fprintf(cgiOut, "</option></select>");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "select RSA key size here</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=radio name=keytype value=dsa></th>");
   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#CFCFCF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000000\">");
   fprintf(cgiOut, "<b>Generate DSA key pair</b></td>");

   fprintf(cgiOut, "<td align=\"center\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<select name=\"dsastrength\">");
   fprintf(cgiOut, "<option value=\"512\">Key Strength: 512 bit (Poor)</option>");
   fprintf(cgiOut, "<option value=\"1024\" selected>");
   fprintf(cgiOut, "Key Strength: 1024 bit (Good)</option>");
   fprintf(cgiOut, "<option value=\"2048\">Key Strength: 2048 bit (Better)</option>");
   fprintf(cgiOut, "<option value=\"4096\">Key Strength: 4096 bit (Best)");
   fprintf(cgiOut, "</option></select>");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "<td align=\"left\" bgcolor=\"#AFAFAF\">");
   fprintf(cgiOut, "<font size=\"2\" face=\"Arial\" color=\"#000080\">");
   fprintf(cgiOut, "select DSA key size here</td>");
   fprintf(cgiOut, "</tr>");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Generate\">");

   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "</form>");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot();
   return(0);
}
