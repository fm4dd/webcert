/* -------------------------------------------------------------------------- *
 * file:         certexport.c                                                 *
 * purpose:      provides a download link to the certificate. It loads the    *
 *               certificate from the CA cert store and writes a copy to the  *
 *               web export directory, converting the certificate format if   *
 *               necessary. In the case of PKCS12, it requests the private    *
 *               key along with a passphrase for protection.                  *
 * hint:         call it with ?cfilename=<xxx.pem>&format=[pem|der|p12]       *
 * -------------------------------------------------------------------------- */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cgic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include "webcert.h"

/* ---------------------------------------------------------- *
 * key_validate() does a basic check for a Key's PEM format   *
 * ---------------------------------------------------------- */
void key_validate(char *);

int cgiMain() {

   char			format[4]           = "";
   X509			*cert               = NULL;
   X509			*cacert             = NULL;
   STACK_OF(X509)	*cacertstack        = NULL;
   PKCS12		*pkcs12bundle       = NULL;
   EVP_PKEY		*cert_privkey       = NULL;
   BIO			*inbio              = NULL;
   BIO			*outbio             = NULL;
   char 		certfilepath[255]   = "";
   char 		certnamestr[81]     = "";
   char 		certfilestr[81]     = "[n/a]";
   FILE 		*cacertfile         = NULL;
   FILE 		*certfile           = NULL;
   char 		exportfilestr[81]   = "[n/a]";
   FILE 		*exportfile         = NULL;
   int			bytes               = 0;
   char 		title[41]           = "Download Certificate";
   char 		privkeystr[KEYLEN]  = "";
   char 		privkeytst[KEYLEN]  = "";
   char			p12pass[P12PASSLEN] = "";
   char			cainc[4]            = "";

/* -------------------------------------------------------------------------- *
 * verify if the cgi parameters have been provided correctly                  *
 * ---------------------------------------------------------------------------*/

   if (! (cgiFormString("cfilename", certfilestr, sizeof(certfilestr))
                                                        == cgiFormSuccess))
      int_error("Error getting >cfilename< from calling form");

   if (cgiFormString("format", format, sizeof(format)) == cgiFormSuccess) {
      if (! ( (strcmp(format, "pem") == 0) ||
              (strcmp(format, "der") == 0) ||
              (strcmp(format, "p12") == 0)
            )
         )
         int_error("Error URL >format< parameter is not [pem|der|p12]");
   }
   else int_error("Error getting the >format< parameter in URL");

/* -------------------------------------------------------------------------- *
 * Since we process a file outside the webroot, we make sure no "../.." comes *
 * from the calling URL or else sensitive files could be read and we have a   *
 * huge security problem. We scan and must reject all occurrences of '..' '/' *
 * -------------------------------------------------------------------------- */

   if ( strstr(certfilestr, "..") ||
        strchr(certfilestr, '/')  ||
      ! strstr(certfilestr, ".pem")
      )
      int_error("Error incorrect data in >cfilename<");

/* -------------------------------------------------------------------------- *
 * strip off the file format extension from the file name                     *
 * ---------------------------------------------------------------------------*/

   strncpy(certnamestr, certfilestr, sizeof(certnamestr));
   strtok(certnamestr, ".");

/* -------------------------------------------------------------------------- *
 * create the export file name and check if the format was already exported   *
 * ---------------------------------------------------------------------------*/

   snprintf(exportfilestr, sizeof(exportfilestr), "%s/%s.%s",
                           CERTEXPORTDIR, certnamestr, format);

   if (access(exportfilestr, R_OK) == 0) {
   /* ----------------------------------------------------------------------- *
    * start the html output                                                   *
    * ------------------------------------------------------------------------*/
      pagehead(title);
      fprintf(cgiOut, "<table>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>");
      fprintf(cgiOut, "Download URL for certificate %s in %s format",
                                                          certnamestr, format);
      fprintf(cgiOut, "</th>");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"center\">");
      fprintf(cgiOut, "<a href=\"http://%s%s/%s.%s\">",
                       cgiServerName, CERTEXPORTURL, certnamestr, format);
      fprintf(cgiOut, "http://%s%s/%s.%s</a>",
                       cgiServerName, CERTEXPORTURL, certnamestr, format);
      fprintf(cgiOut, "</td>");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>\n");
      fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
      fprintf(cgiOut, "<input type=\"submit\" value=\"Return\" />\n");
      fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
      fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
      fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\" />\n");
      fprintf(cgiOut, "</form>\n");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "</table>\n");
      pagefoot();
      return(0);
   }

/* -------------------------------------------------------------------------- *
 * If the requested format is PKCS12, check if private key and cacert include *
 * flag was provided. Otherwise request private key and cacert include flag.  *
 * ---------------------------------------------------------------------------*/
   if (strcmp(format, "p12") == 0 &&
       (! (cgiFormString("certkey", privkeystr, KEYLEN) == cgiFormSuccess ) ||
        ! (cgiFormString("p12pass", p12pass, P12PASSLEN) == cgiFormSuccess ))) {

      snprintf(title, sizeof(title), "Export %s as a PKCS12 container",
                           certfilestr);
   /* ----------------------------------------------------------------------- *
    * start the html output                                                   *
    * ------------------------------------------------------------------------*/
      pagehead(title);
      fprintf(cgiOut, "<form action=\"certexport.cgi\" method=\"post\">");
      fprintf(cgiOut, "<table>\n");
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th colspan=\"2\">");
      fprintf(cgiOut, "Please paste your certificate's private key into the ");
      fprintf(cgiOut, "field below (PEM format):");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"getcert\" colspan=\"2\">\n");
      fprintf(cgiOut, "<textarea name=\"certkey\" cols=\"64\" rows=\"13\">");
      fprintf(cgiOut, "</textarea>");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"desc\" colspan=\"2\">");
      fprintf(cgiOut, "To create a PKCS12 certificate bundle,");
      fprintf(cgiOut, " the certificate's private key is required.");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"type250\">");
      fprintf(cgiOut, "Passphrase to protect the PKCS12 file");
      fprintf(cgiOut, "<br />(max 40 chars):");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "<td>");
      fprintf(cgiOut, "<input type=\"password\" name=\"p12pass\" class=\"p12pass\"/>");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"desc\" colspan=\"2\">");
      fprintf(cgiOut, "Because the PKCS12 certificate bundle contains the");
      fprintf(cgiOut, " private key, the file needs to be secured by a passphrase.");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"type\">");
      fprintf(cgiOut, "Include the CA certificate in the container");
      fprintf(cgiOut, "<br />(default yes):");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "<td id=\"cainc_td\">");
      fprintf(cgiOut, "<input type=\"checkbox\" name=\"cainc\" ");
      fprintf(cgiOut, "value=\"yes\" checked=\"checked\" id=\"cainc_cb\" ");
      fprintf(cgiOut, "onclick=\"switchGrey('cainc_cb', 'cainc_td', 'none', 'none');\" />");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<td class=\"desc\" colspan=\"2\">");
      fprintf(cgiOut, "PKCS12 certificate bundles can also carry the signing ");
      fprintf(cgiOut, " CA certificate, this is generally the best option.");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");

      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th colspan=\"2\">");
      fprintf(cgiOut, "<input type=\"submit\" value=\"Generate PKCS12\" />");
      fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
      fprintf(cgiOut, "value=\"%s\" />", certfilestr);
      fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"p12\" />");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "</tr>\n");
      fprintf(cgiOut, "</table>\n");
      fprintf(cgiOut, "</form>\n");
      pagefoot();
      return(0);
   }

/* -------------------------------------------------------------------------- *
 * These function calls are essential to make many PEM + other openssl        *
 * functions work.                                                            *
 * -------------------------------------------------------------------------- */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

/* -------------------------------------------------------------------------- *
 * read the certstore certificate and define a BIO output stream              *
 * ---------------------------------------------------------------------------*/

   if (strcmp(certfilestr, "cacert.pem") == 0) 
      snprintf(certfilepath, sizeof(certfilepath), "%s", CACERT);
   else
      snprintf(certfilepath, sizeof(certfilepath), "%s/%s", CACERTSTORE,
                                                                certfilestr);
   if (! (certfile = fopen(certfilepath, "r")))
      int_error("Error cant read cert store certificate file");

   if (! (cert = PEM_read_X509(certfile,NULL,NULL,NULL)))
      int_error("Error loading cert into memory");

   outbio = BIO_new(BIO_s_file());

/* -------------------------------------------------------------------------- *
 *  write the certificate in the specified export format to the wbcert export *
 *  directory, named after its serial number.                                 *
 * ---------------------------------------------------------------------------*/

   if (strcmp(format, "pem") == 0) {
     if (! (exportfile=fopen(exportfilestr, "w")))
        printf("Error open PEM certificate file for writing.\n");
     BIO_set_fp(outbio, exportfile, BIO_NOCLOSE);
     if (! PEM_write_bio_X509(outbio, cert))
        int_error("Error writing PEM certificate to export directory.");
     fclose(exportfile);
   }
   if (strcmp(format, "der") == 0) {
     if (! (exportfile=fopen(exportfilestr, "w")))
        printf("Error open DER certificate file for writing.\n");
     BIO_set_fp(outbio, exportfile, BIO_NOCLOSE);
     bytes = i2d_X509_bio(outbio, cert);
     if (bytes <= 0)
        int_error("Error writing DER certificate to export directory.");
     fclose(exportfile);
   }
   if (strcmp(format, "p12") == 0) {
     if (strcmp(certfilestr, "cacert.pem") == 0) 
        int_error("Error CA certificate can't be converted to PKCS12.");

     if (! (cgiFormString("cainc", cainc, sizeof(cainc)) == cgiFormSuccess ))
        int_error("Error missing CA certificate include flag.");

     /* initialize the structures */
     if ((pkcs12bundle = PKCS12_new()) == NULL)
        int_error("Error creating PKCS12 structure.");
     if ((cert_privkey = EVP_PKEY_new()) == NULL)
        int_error("Error creating EVP_PKEY structure.");
     if ((cacertstack = sk_X509_new_null()) == NULL)
        int_error("Error creating STACK_OF(X509) structure.");

     /* -------------------------------------------------------------------- *
      * check if a key was pasted with the BEGIN and END                     *
      * lines, assuming the key data in between is intact                    *
      * -------------------------------------------------------------------- */
      key_validate(privkeystr);

     /* -------------------------------------------------------------------- *
      * input seems OK, write the key to a temporary mem BIO and load it     *
      * -------------------------------------------------------------------- */
      inbio = BIO_new_mem_buf(privkeytst, -1);
      if (! (cert_privkey = PEM_read_bio_PrivateKey( inbio, NULL, NULL, NULL)))
        int_error("Error loading certificate private key content");

     if (strcmp(cainc, "yes") == 0) {
        /* load the CA certificate */
        if (! (cacertfile = fopen(CACERT, "r")))
           int_error("Error can't open CA certificate file");
        if (! (cacert = PEM_read_X509(cacertfile,NULL,NULL,NULL)))
           int_error("Error loading CA certificate into memory");
        fclose(cacertfile);
        sk_X509_push(cacertstack, cacert);
     }

     /* values of zero use the openssl default values */
     pkcs12bundle = PKCS12_create( p12pass,     // certbundle access password
                                   certnamestr, // friendly certname
                                   cert_privkey,// the certificate private key
                                   cert,        // the main certificate
                                   cacertstack, // stack of CA cert chain
                                   0,           // int nid_key (default 3DES)
                                   0,           // int nid_cert (40bitRC2)
                                   0,           // int iter (default 2048)
                                   0,           // int mac_iter (default 1)
                                   0            // int keytype (default no flag)
                                 );
     if ( pkcs12bundle == NULL)
        int_error("Error generating a valid PKCS12 structure.");

     if (! (exportfile=fopen(exportfilestr, "w")))
        printf("Error open PKCS12 certificate file bundle for writing.\n");
     bytes = i2d_PKCS12_fp(exportfile, pkcs12bundle);
     if (bytes <= 0)
        printf("Error writing PKCS12 certificate to export directory.\n");

     fclose(exportfile);
     sk_X509_free(cacertstack);
     PKCS12_free(pkcs12bundle);
   }
   BIO_free(outbio);

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/
   pagehead(title);
   fprintf(cgiOut, "<table>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>");
   fprintf(cgiOut, "%s certificate in %s format", certfilestr, format);
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<a href=\"http://%s%s/%s.%s\">\n",
                    cgiServerName, CERTEXPORTURL, certnamestr, format);
   fprintf(cgiOut, "http://%s%s/%s.%s</a>\n",
                    cgiServerName, CERTEXPORTURL, certnamestr, format);
   fprintf(cgiOut, "</td>\n");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th>\n");
   fprintf(cgiOut, "<form action=\"getcert.cgi\" method=\"post\">\n");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Return\" />\n");
   fprintf(cgiOut, "<input type=\"hidden\" name=\"cfilename\" ");
   fprintf(cgiOut, "value=\"%s\" />\n", certfilestr);
   fprintf(cgiOut, "<input type=\"hidden\" name=\"format\" value=\"pem\" />\n");
   fprintf(cgiOut, "</form>\n");
   fprintf(cgiOut, "</th>\n");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");
   pagefoot();
   return(0);
}
