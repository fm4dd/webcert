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
   fprintf(cgiOut, "<th colspan=\"4\">");
   fprintf(cgiOut, "To generate a certificate request, please fill out ");
   fprintf(cgiOut, "the fields below:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>C</th>");
   fprintf(cgiOut, "<td class=\"type\">Country</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"c\" size=\"20\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "US, GB, DE, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>ST</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "State or Province</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"st\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "CA, NV, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>L</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Location, City</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"l\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Rocklin, Los Angeles, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>O</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Organisation, Company</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"o\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Frank4DD, ACME Corp, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>OU</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Dept or Subdivision</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"ou\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Support, Sales, etc</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>eA</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "E-Mail Address</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"email\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "you@somewhere.com</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>CN</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "System Name *</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"cn\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "i.e. www.fm4dd.com</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">");
   fprintf(cgiOut, "Optional: For serving multiple domains or IP's, set additional Host- or IP values:");
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
   fprintf(cgiOut, "<th>GN</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Given Name</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"gn\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "First Name, i.e. John, Paul</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>SN</th>");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Surname</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=\"text\" name=\"sn\" size=\"40\" value=\"\" />");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "Last Name, i.e. Doe, Miller</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">");
   fprintf(cgiOut, "Select the algorithm and strength of the public/private key pair:");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"radio\" id=\"rsa_rb\" checked=\"checked\" name=\"keytype\" value=\"rsa\" onclick=\"switchGrey('rsa_rb', 'rsa', 'dsa', 'ecc');\" /></th>\n");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Generate RSA key pair</td>\n");

   fprintf(cgiOut, "<td id=\"rsa\">");
   fprintf(cgiOut, "<select name=\"rsastrength\">\n");
   fprintf(cgiOut, "<option value=\"512\">Key Strength: 512 bit (Poor)</option>\n");
   fprintf(cgiOut, "<option value=\"1024\">Key Strength: 1024 bit (Fair)</option>\n");
   fprintf(cgiOut, "<option value=\"2048\" selected=\"selected\">Key Strength: 2048 bit (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"4096\">Key Strength: 4096 bit (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");

   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "select RSA key size here</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"radio\" id=\"dsa_rb\" name=\"keytype\" value=\"dsa\" onclick=\"switchGrey('dsa_rb', 'dsa', 'rsa', 'ecc');\" /></th>\n");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Generate DSA key pair</td>\n");

   fprintf(cgiOut, "<td id=\"dsa\" style=\"background-color: #CFCFCF;\">");
   fprintf(cgiOut, "<select name=\"dsastrength\">\n");
   fprintf(cgiOut, "<option value=\"512\">Key Strength: 512 bit (Poor)</option>\n");
   fprintf(cgiOut, "<option value=\"1024\">Key Strength: 1024 bit (Fair)</option>\n");
   fprintf(cgiOut, "<option value=\"2048\" selected=\"selected\">Key Strength: 2048 bit (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"4096\">Key Strength: 4096 bit (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");

   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "select DSA key size here</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "<input type=\"radio\" id=\"ecc_rb\" name=\"keytype\" value=\"ecc\" onclick=\"switchGrey('ecc_rb', 'ecc', 'rsa', 'dsa');\" /></th>\n");
   fprintf(cgiOut, "<td class=\"type\">");
   fprintf(cgiOut, "Generate ECC key pair</td>\n");

   fprintf(cgiOut, "<td id=\"ecc\" style=\"background-color: #CFCFCF;\">");
   fprintf(cgiOut, "<select name=\"eccstrength\">\n");
   fprintf(cgiOut, "<option value=\"secp224r1\">Key Type: secp224r1 (OK)</option>\n");
   fprintf(cgiOut, "<option value=\"secp256k1\" selected=\"selected\">Key Type: secp256k1 (Good)</option>\n");
   fprintf(cgiOut, "<option value=\"secp384r1\">Key Type: secp384r1 (Better)</option>\n");
   fprintf(cgiOut, "<option value=\"secp521r1\">Key Type: secp521r1 (Best)");
   fprintf(cgiOut, "</option>\n</select>");
   fprintf(cgiOut, "</td>\n");

   fprintf(cgiOut, "<td class=\"desc\">");
   fprintf(cgiOut, "select ECC key size here</td>");
   fprintf(cgiOut, "</tr>\n");


   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=\"4\">");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Generate\" />");

   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   fprintf(cgiOut, "* Mandatory field: Can be set with a DNS name, IP address, serial number, or any other identifier.\n");
   fprintf(cgiOut, "</form>");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot();
   return(0);
}
