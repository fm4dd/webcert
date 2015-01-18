/* -------------------------------------------------------------------------- *
 * file:         certvalidate.c                                               *
 * purpose:      validate a certificate against a root certificate chains     *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "webcert.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#define MAXFLAGS 15
#define CB_STRLEN 255
#define MOZI_PREFIX "mozilla-bundle-"
#define VERI_PREFIX "verisign-bundle-"
#define SUSE_PREFIX "opensuse-bundle-"

/* ---------------------------------------------------------- *
 * get_latest_ca_bundle() checks for the most recent file     *
 * containing  MOZI_PREFIX or VERI_PREFIX in CABUNDLEDIR,     *
 * puts this file path to the string arg & ret the # of files *
 * ---------------------------------------------------------- */
int get_latest_ca_bundle(char[]);

/* ---------------------------------------------------------- *
 * X509_load_ca_file() loads a CA file into a mem BIO using   *
 * (BIO_read_filename(), PEM_X509_INFO_read_bio() puts them   *
 * in a stack, which is then to be added to a store or CTX.   *
 * ---------------------------------------------------------- */
STACK_OF(X509_INFO) *X509_load_ca_file(int *cert_counter,
                      struct stat *fstat, const char *file);

/* ---------------------------------------------------------- *
 * verify_mem_store() puts the CA info stack into a store     *
 * struct, which is then passed to the CTX during the init.   *
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_mem_store(STACK_OF(X509_INFO) *st);

//static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

/* ---------------------------------------------------------- * 
 * For a remote server cert validation we need a TCP socket.  * 
 * create_socket() creates the socket & TCP-connect to server * 
 * ---------------------------------------------------------- */
int create_socket(char url_str[]);

/* ---------------------------------------------------------- *
 * This function is taken from openssl/crypto/asn1/t_x509.c.  *
 * ---------------------------------------------------------- */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);

/* ---------------------------------------------------------- *
 * This function adds missing OID's to the internal structure *
 * ---------------------------------------------------------- */
void add_missing_ev_oids();

/* ---------------------------------------------------------- *
 * display_cert() shows certificate details in a HTML table.  *
 * ---------------------------------------------------------- */
void display_cert(X509 *ct, char ct_type[], char chain_type[], int level);

/* ---------------------------------------------------------- *
 * Global variable definition                                 *
 * ---------------------------------------------------------- */
BIO              *certbio = NULL;
BIO               *outbio = NULL;
BIO                *cabio = NULL;
X509                *cert = NULL;
char      error_str[4096] = "";
char *file_prefix;

int cgiMain() {

  X509_STORE_CTX  *vrfy_ctx = NULL;
  X509_VERIFY_PARAM *param  = NULL;
  STACK_OF(X509_INFO) *list = NULL;
  int            cert_fsize = 0;
  int            veri_fsize = 0;
  int          wcca_counter = 0;
  int          veri_counter = 0;
  int          suse_counter = 0;
  int          wbct_counter = 0;
  char          **form_data = NULL;  /* string array for query data */
  char cafilestr[CB_STRLEN] = "";
  struct stat wcca_stat; 
  struct stat veri_stat; 
  struct stat suse_stat; 
  struct stat wbct_stat; 
  time_t now;
  int ret;
  cgiFilePtr file;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  add_missing_ev_oids();
  time(&now);

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(cgiOut, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the CA certificate bundles from a PEM file list and   *
   * count the total number of certificates in it.              *
   * ---------------------------------------------------------- */

  file_prefix = VERI_PREFIX;
  if(get_latest_ca_bundle(cafilestr) > 0) {
    list = X509_load_ca_file(&veri_counter, &veri_stat, cafilestr);
    sk_X509_INFO_pop_free(list, X509_INFO_free);
  }

  file_prefix = MOZI_PREFIX;
  if(get_latest_ca_bundle(cafilestr) > 0) {
    list = X509_load_ca_file(&wcca_counter, &wcca_stat, cafilestr);
    sk_X509_INFO_pop_free(list, X509_INFO_free);
  }

  file_prefix = SUSE_PREFIX;
  if(get_latest_ca_bundle(cafilestr) > 0) {
    list = X509_load_ca_file(&suse_counter, &suse_stat, cafilestr);
    sk_X509_INFO_pop_free(list, X509_INFO_free);
  }

  //list=sk_X509_INFO_new_null();
  list = X509_load_ca_file(&wbct_counter, &wbct_stat, CACERT);
  sk_X509_INFO_pop_free(list, X509_INFO_free);

  /* ---------------------------------------------------------- *
   * If called w/o arguments, display the data gathering form.  *
   * ---------------------------------------------------------- */
  if (cgiFormEntries(&form_data) != cgiFormSuccess)
    int_error("Error: Could not retrieve CGI form data.");

  if(form_data[0] == NULL) {

  static char title[] = "Certificate Validation Request";

  /* ---------------------------------------------------------- *
   * start the html output                                      *
   * -----------------------------------------------------------*/
    pagehead(title);
  
    fprintf(cgiOut, "<form enctype=\"multipart/form-data\" action=\"certvalidate.cgi\" method=\"post\">\n");
  
    fprintf(cgiOut, "<table width=\"100%%\">\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Select a certificate for verification");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
  
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "<input type=\"radio\" id=\"lf_rb\" name=\"crt_type\" value=\"lf\" checked=\"checked\" onclick=\"switchGrey('lf_rb', 'lf', 'ru', 'none');\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Upload Your certificate (PEM format)");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"lf\">\n");
    fprintf(cgiOut, "<input type=\"file\" name=\"requestfile\" style=\"background:#ccc; width: 100%%\" />\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "<input type=\"radio\" id=\"ru_rb\" name=\"crt_type\" value=\"ru\" onclick=\"switchGrey('ru_rb', 'ru', 'lf', 'none');\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Remote certificate check - type URL");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td id=\"ru\" style=\"background-color: #CFCFCF;\">\n");
    fprintf(cgiOut, "<input type=\"text\" name=\"requesturl\" value=\"https://www.verisign.com\" ");
    fprintf(cgiOut, "style=\"background:#ccc; width: 100%%\" />\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<td class=\"desc\" colspan=\"3\">\n");
    fprintf(cgiOut, "Here we select the certificate we would like to validate.\n");
    fprintf(cgiOut, "If it is a local file on your PC, it needs to be PEM-encoded. ");
    fprintf(cgiOut, "Alternatively, we can provide the URL to validate a server ");
    fprintf(cgiOut, "certificate, i.e. https://www.verisign.com.\n");
    fprintf(cgiOut, "Because the certificate validation happens low-level, non-http ");
    fprintf(cgiOut, "ports like ldaps or imaps can also be specified here. More examples:\n");
    fprintf(cgiOut, "<ul><li>https://server.domain.tld:8883</li>\n");
    fprintf(cgiOut, "<li>ldaps://fm4dd.com</li>\n");
    fprintf(cgiOut, "<li>imaps://fm4dd.com</li>\n");
    fprintf(cgiOut, "</ul>\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "<p></p>\n");
   
    fprintf(cgiOut, "<table width=\"100%%\">\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"3\">");
    fprintf(cgiOut, "Select the Root CA certificate file or bundle to use");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
  
    if (wcca_counter) {
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>\n");
      fprintf(cgiOut, "<input type=\"radio\" name=\"cab_type\" value=\"mz\" checked=\"checked\" />\n");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "<td colspan=\"2\">");
      fprintf(cgiOut, "<b>WebCert internal CA certificates</b> - %d certificates, %ld Bytes, last update %s</td>\n",
                      wcca_counter, wcca_stat.st_size, ctime(&wcca_stat.st_mtime));
      fprintf(cgiOut, "</tr>\n");
    }
    if (veri_counter) {
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>\n");
      fprintf(cgiOut, "<input type=\"radio\" name=\"cab_type\" value=\"vs\" />\n");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "<td colspan=\"2\">\n");
      fprintf(cgiOut, "<b>Verisign Root certificate bundle</b> - %d certificates, %ld Bytes, last update %s</td>\n",
                      veri_counter, veri_stat.st_size, ctime(&veri_stat.st_mtime));
      fprintf(cgiOut, "</tr>\n");
    }
    if (suse_counter) {
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>");
      fprintf(cgiOut, "<input type=\"radio\" name=\"cab_type\" value=\"os\" />");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "<td colspan=\"2\">");
      fprintf(cgiOut, "<b>OpenSuse Root certificates</b> - %d certificates, %ld Bytes, last update %s</td>\n",
                      suse_counter, suse_stat.st_size, ctime(&suse_stat.st_mtime));
      fprintf(cgiOut, "</tr>\n");
    }
    if (wbct_counter) {
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>");
      fprintf(cgiOut, "<input type=\"radio\" name=\"cab_type\" value=\"wc\" />");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "<td colspan=\"2\">");
      fprintf(cgiOut, "<b>WebCert's own Root certificate</b> - %d certificates, %ld Bytes, last update %s</td>\n",
                      wbct_counter, wbct_stat.st_size, ctime(&wbct_stat.st_mtime));
      fprintf(cgiOut, "</tr>\n");
    }
  
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>");
    fprintf(cgiOut, "<input type=\"radio\" name=\"cab_type\" value=\"pc\" />");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td class=\"type250\">");
    fprintf(cgiOut, "Your CA certificate(s) - PEM format:");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "<input type=\"file\" name=\"cabundlefile\" style=\"color:#f00; background:#ccc; width: 100%%\" />");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<td class=\"desc\" colspan=\"3\">");
    fprintf(cgiOut, "Here we select the list of CA certificates we would like to validate against. ");
    fprintf(cgiOut, "Three bundles are prepared: ");
    fprintf(cgiOut, "<ul>");
    fprintf(cgiOut, "<li>WebCert's internal CA certificate list is manually upated with ");
    fprintf(cgiOut, "CA certificates from major commercial Vendors.</li> ");
    fprintf(cgiOut, "<li> The Verisign Root certificate list is downloaded and converted  ");
    fprintf(cgiOut, "weekly from Verisign.</li>");
    fprintf(cgiOut, "<li> The WebCert Root certificate is WebCerts own single CA file, ");
    fprintf(cgiOut, "validating certificates for this CA only.</li>");
    fprintf(cgiOut, "</ul>");
    fprintf(cgiOut, "Alternatively, you can upload your own, local CA certificate file or file bundle (Apache-style) in PEM format.");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "<p></p>\n");
  
    fprintf(cgiOut, "<table width=\"100%%\">\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"2\">\n");
    fprintf(cgiOut, "Additional validation settings (optional and advanced)\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
 
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "<select name=\"depth\">");
    fprintf(cgiOut, "<option value=\"0\">0</option>");
    fprintf(cgiOut, "<option value=\"1\">1</option>");
    fprintf(cgiOut, "<option value=\"2\">2</option>");
    fprintf(cgiOut, "<option value=\"3\">3</option>");
    fprintf(cgiOut, "<option value=\"4\">4</option>");
    fprintf(cgiOut, "<option value=\"5\">5</option>");
    fprintf(cgiOut, "<option value=\"6\">6</option>");
    fprintf(cgiOut, "<option value=\"7\">7</option>");
    fprintf(cgiOut, "<option value=\"8\" selected=\"selected\">8</option>");
    fprintf(cgiOut, "<option value=\"9\">9</option>");
    fprintf(cgiOut, "<option value=\"10\">10</option>");
    fprintf(cgiOut, "<option value=\"11\">11</option>");
    fprintf(cgiOut, "<option value=\"12\">12</option>");
    fprintf(cgiOut, "<option value=\"13\">13</option>");
    fprintf(cgiOut, "<option value=\"14\">14</option>");
    fprintf(cgiOut, "<option value=\"15\">15</option>");
    fprintf(cgiOut, "</select>\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td>\n");
    fprintf(cgiOut, "<b>SSL_set_verify_depth</b> - limit or expand the chain verification to the specified depth.\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");
  
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>\n");
    fprintf(cgiOut, "<input type=\"checkbox\" name=\"X509_V_FLAG_X509_STRICT\" id=\"strict_cb\" onclick=\"switchGrey('strict_cb', 'strict_td', 'none', 'none');\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td id=\"strict_td\" style=\"background-color: #CFCFCF;\">\n");
    fprintf(cgiOut, "<b>X509_V_FLAG_X509_STRICT</b> - disable workarounds, verify strictly per X509 rules.\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");
  
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<td class=\"desc\" colspan=\"2\">\n");
    fprintf(cgiOut, "Here we can select additional OpenSSL settings that control and fine-tune the validation ");
    fprintf(cgiOut, "process. They are optional, and require expert knowledge ");
    fprintf(cgiOut, "to interpret results correctly. In doubt, leave them alone.\n");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "<p></p>\n");
  
    fprintf(cgiOut, "<table width=\"100%%\">\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"2\">\n");
    fprintf(cgiOut, "<input type=\"submit\" value=\"Verify\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "<p></p>\n");
  
    fprintf(cgiOut, "</form>\n");
  }
  /* ---------------------------------------------------------- *
   * Do a validation and display the verification results here. *
   * -----------------------------------------------------------*/
  else {
    STACK_OF(X509) *rem_chain = NULL;
    SSL_CTX          *ssl_ctx = NULL;
    SSL                  *ssl = NULL;
    int       rem_chain_count = 0;
    static char       title[] = "Certificate Validation Report";
    char          crt_type[3] = "";
    char          cab_type[3] = "";
    char       req_name[1024] = "";
    char        url_str[1024] = "";
    int                 depth = 0;

  /* ---------------------------------------------------------- *
   * check the CGI form data: first check for the given cert    *
   * -----------------------------------------------------------*/
    /* check if we got the crt_type submitted */
    if (cgiFormString("crt_type", crt_type, sizeof(crt_type))
                                                     != cgiFormSuccess )
      int_error("Error retrieving the forms cert request type.");

    /* check if the cert was a local uploaded file (lf), or if  *
     * we must retrieve it from a remote url (ru).              */
    if ((strcmp(crt_type, "lf") != 0) && (strcmp(crt_type, "ru") != 0)) {
      snprintf(error_str, sizeof(error_str), "Unknown parameter for the cert request type: %s.", crt_type);
      int_error(error_str);
    }

   /* check if we received a depth value. If not we set it to 8 */
   if(cgiFormInteger("depth", &depth, 8) == cgiFormSuccess)
     if(depth <0 || depth >15) {
       snprintf(error_str, sizeof(error_str), "Depth parameter outside valid range: %d.", depth);
       int_error(error_str);
     }

    /* get the uploaded certificate data and put it into the certbio */
    if (strcmp(crt_type, "lf") == 0) {
      char     req_form[REQLEN] = "";

      ret = cgiFormFileName("requestfile", req_name, sizeof(req_name));
      if (ret !=cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Could not get the certificate filename, return code %d", ret);
        int_error(error_str);
      }

      cgiFormFileSize("requestfile", &cert_fsize);

      /* we open the file to get a file handle */
      if (cgiFormFileOpen("requestfile", &file) != cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Cannot open the uploaded certificate file %s", req_name);
        int_error(error_str);
      }

      /* we read the file content into the req_form buffer */
      if (! (cgiFormFileRead(file, req_form, REQLEN, &cert_fsize) == cgiFormSuccess)) {
        snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded certificate file %s", req_name);
        int_error(error_str);
      }

      /* Create the memory BIO for the certificate to verify */
      certbio = BIO_new_mem_buf(req_form, -1);

      /* Try to read the cert buffer into the X509 structure */
      if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        snprintf(error_str, sizeof(error_str), "Error reading cert structure of %s into memory", req_name);
        int_error(error_str);
      }
    }

    if (strcmp(crt_type, "ru") == 0) {
      const SSL_METHOD *method;
      int server;

      if (! (cgiFormString("requesturl", url_str, sizeof(url_str)) == cgiFormSuccess))
        int_error("Error getting the URL from the calling form");

      /* initialize SSL library and register algorithms */
      if(SSL_library_init() < 0)
        int_error("Could not initialize the OpenSSL library !");

      /* Bring in and register SSL error messages */
      SSL_load_error_strings();

      /* Set SSLv2 client hello, also announce SSLv3 and TLSv1 */
      method = SSLv23_client_method();

      /* Try to create a new SSL context */
      if ( (ssl_ctx = SSL_CTX_new(method)) == NULL)
        int_error("Unable to create a new SSL context structure.");

      /* Disabling SSLv2 will leave v3 and TSLv1 for negotiation */
      SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

      /* Create new SSL connection state */
      ssl = SSL_new(ssl_ctx);

      /* Make the underlying TCP socket connection */
      server = create_socket(url_str);

      /* Attach the SSL session to the socket descriptor */
      SSL_set_fd(ssl, server);

      /* Try to SSL-connect here, returns 1 for success */
      if ( SSL_connect(ssl) != 1 ) {
        snprintf(error_str, sizeof(error_str), 
                 "Error could not make a SSL connection to %s.", url_str);
        int_error(error_str);
      }

      /* Get the remote certificate into the X509 structure */
      cert = SSL_get_peer_certificate(ssl);
      if (cert == NULL) {
        snprintf(error_str, sizeof(error_str), 
                 "Error could not get a certificate from %s.", url_str);
        int_error(error_str);
      }

      /* We are trying to get the intermediates from remote */
      rem_chain = SSL_get_peer_cert_chain(ssl);
      if(rem_chain != NULL) rem_chain_count = sk_X509_num(rem_chain);

      /* calculate the PEM file size, putting the cert into a BIO */
      cert_fsize = 0;
      int tmp;

      /* Create the memory BIO for the certificate to verify */
      certbio = BIO_new(BIO_s_mem());

      PEM_write_bio_X509(certbio, cert);
      while ((BIO_read(certbio, &tmp, 1)) >0) {
        cert_fsize++;
      }

      /* Free the SSL structures we don't need anymore */
      close(server);
      //SSL_free(ssl);
      //SSL_CTX_free(ssl_ctx);
    }

  /* ---------------------------------------------------------- *
   * check the CGI form data: next check for the ca bundle file *
   * -----------------------------------------------------------*/
    char     cab_form[REQLEN] = "";
    char       cab_name[1024] = "";

    /* check if we got the cab_type submitted */
    if (cgiFormString("cab_type", cab_type, sizeof(cab_type))
                                                     != cgiFormSuccess )
      int_error("Error retrieving the forms CA bundle type.");

    /* check if the bundle type is either mz, vs, wc or pc */
    if ((strcmp(cab_type, "mz") != 0) && (strcmp(cab_type, "vs") != 0)
     && (strcmp(cab_type, "wc") != 0) && (strcmp(cab_type, "pc") != 0)
     && (strcmp(cab_type, "os") != 0)) {
      snprintf(error_str, sizeof(error_str), "Unknown parameter for the CA bundle type: %s.", cab_type);
      int_error(error_str);
    }

    if (strcmp(cab_type, "mz") == 0) {
      file_prefix = MOZI_PREFIX;
      if(get_latest_ca_bundle(cafilestr) > 0) {
        list = X509_load_ca_file(&veri_counter, &veri_stat, cafilestr);
      }
    }

    if (strcmp(cab_type, "vs") == 0) {
      file_prefix = VERI_PREFIX;
      if(get_latest_ca_bundle(cafilestr) > 0) {
        list = X509_load_ca_file(&veri_counter, &veri_stat, cafilestr);
      }
    }

    if (strcmp(cab_type, "os") == 0) {
      file_prefix = SUSE_PREFIX;
      if(get_latest_ca_bundle(cafilestr) > 0) {
        list = X509_load_ca_file(&veri_counter, &veri_stat, cafilestr);
      }
    }

    if (strcmp(cab_type, "wc") == 0)
      list = X509_load_ca_file(&veri_counter, &veri_stat, CACERT);

    /* if we got type pc, we need to process the user-submitted file */
    if (strcmp(cab_type, "pc") == 0) {
      if (cgiFormFileName("cabundlefile", cab_name, sizeof(cab_name))
                                                       !=cgiFormSuccess)
        int_error("Could not retrieve the forms certificate filename\n");

      /* we open the file to get a file handle */
      if (cgiFormFileOpen("cabundlefile", &file) != cgiFormSuccess) {
        snprintf(error_str, sizeof(error_str), "Cannot open the uploaded certificate file %s", cab_name);
        int_error(error_str);
      }

      /* we read the file content into the cab_form buffer */
      if (! (cgiFormFileRead(file, cab_form, REQLEN, &veri_fsize) == cgiFormSuccess)) {
        snprintf(error_str, sizeof(error_str), "Cannot read data from the uploaded certificate bundle file %s", cab_name);
        int_error(error_str);
      }

      /* we put the buffer data into a memory BIO */
      cabio = BIO_new_mem_buf(cab_form, -1);

      /* we load the buffer data into a certificate stack */
      list = PEM_X509_INFO_read_bio(cabio, NULL, NULL, NULL);
      veri_counter = sk_X509_INFO_num(list);
    }

    /* check if we got any usable CA certificates */
    if (veri_counter == 0) int_error("No certificates found in CA bundle.");
    
  /* ---------------------------------------------------------- *
   * Create a verification context from the stack, add the cert *
   * ---------------------------------------------------------- */
    vrfy_ctx = verify_mem_store(list);

  /* ---------------------------------------------------------- *
   * Set the verification depth and flags for this operation.   *
   * ---------------------------------------------------------- */
    param = X509_VERIFY_PARAM_new();
    X509_VERIFY_PARAM_set_depth(param, depth);

    if (cgiFormCheckboxSingle("X509_V_FLAG_X509_STRICT") == cgiFormSuccess)
      X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);

    //X509_STORE_CTX_set_verify_cb(vrfy_ctx, cert_cb);

  /* ---------------------------------------------------------- *
   * The actual verification operation happens here.            *
   * ---------------------------------------------------------- */
    ret = X509_verify_cert(vrfy_ctx);

  /* ---------------------------------------------------------- *
   * If it was successful, we retrieve all certs in the  chain. *
   * ---------------------------------------------------------- */
    STACK_OF (X509) *res_stack = NULL;

    if(ret == 1) {
      res_stack = X509_STORE_CTX_get_chain(vrfy_ctx);
    }

  /* ---------------------------------------------------------- *
   * start the html output                                      *
   * -----------------------------------------------------------*/
    pagehead(title);

    fprintf(cgiOut, "<h3>Certificate Validation Report</h3>\n");
    fprintf(cgiOut, "<hr />\n");

    fprintf(cgiOut, "<table width=\"100%%\">\n");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"2\">");
    fprintf(cgiOut, "Report Details");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th width=\"70px\">Date:");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, ctime(&now));
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th width=\"70px\">Target:");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td>");
    if(strcmp(crt_type, "lf") == 0) fprintf(cgiOut, req_name);
    if(strcmp(crt_type, "ru") == 0) fprintf(cgiOut, url_str);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>Result:");
    fprintf(cgiOut, "</th>\n");
    if(ret == 0)  fprintf(cgiOut, "<td class=\"failure\">Failure");
    if(ret == 1)  fprintf(cgiOut, "<td class=\"success\">Success");
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>Reason:");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, X509_verify_cert_error_string(vrfy_ctx->error));
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th>Depth:");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td>");
    fprintf(cgiOut, "Maximum Verification Depth: %d ", X509_VERIFY_PARAM_get_depth(param));
    if(ret == 0 ) 
      fprintf(cgiOut, "- Error at Depth Level: %d", X509_STORE_CTX_get_error_depth(vrfy_ctx));
    if(ret == 1 )
      fprintf(cgiOut, "- Verification completed at Depth Level: %d", sk_X509_num(res_stack));
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    if(cgiFormCheckboxSingle("X509_V_FLAG_X509_STRICT") == cgiFormSuccess) {
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>Flags:");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "<td>");
      fprintf(cgiOut, "<b>X509_V_FLAG_X509_STRICT</b> - disable workarounds, verify strictly per X509 rules.");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");
    }

    if(strcmp(crt_type, "ru") == 0) {
      fprintf(cgiOut, "<tr>\n");
      fprintf(cgiOut, "<th>Chain:");
      fprintf(cgiOut, "</th>\n");
      fprintf(cgiOut, "<td>");
      if(rem_chain_count > 1) {
        fprintf(cgiOut, "The remote server provided %d signing certificate(s).", rem_chain_count-1);
        fprintf(cgiOut, " <a href=\"javascript:elementHideShow('rem_chain');\">\n");
        fprintf(cgiOut, "Expand or Hide Chain Details</a>");
      }
      else
        fprintf(cgiOut, "The remote server did not provide the chain of signing certificates.");
      fprintf(cgiOut, "</td>\n");
      fprintf(cgiOut, "</tr>\n");
    }

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th width=\"70px\">CA Bundle:");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "<td>");
    /* display the CA file bundle type here */
    if (strcmp(cab_type, "mz") == 0)
      fprintf(cgiOut, "<b>WebCert internal CA certificates</b> - %d certificates, %ld Bytes, last update %s",
                      veri_counter, veri_stat.st_size, ctime(&veri_stat.st_mtime));
    if (strcmp(cab_type, "vs") == 0)
      fprintf(cgiOut, "<b>Verisign Root certificate bundle</b> - %d certificates, %ld Bytes, last update %s",
                      veri_counter, veri_stat.st_size, ctime(&veri_stat.st_mtime));
    if (strcmp(cab_type, "os") == 0)
      fprintf(cgiOut, "<b>OpenSuse Root certificate bundle</b> - %d certificates, %ld Bytes, last update %s",
                      veri_counter, veri_stat.st_size, ctime(&veri_stat.st_mtime));
    if (strcmp(cab_type, "wc") == 0)
      fprintf(cgiOut, "<b>WebCert's own Root certificate</b> - %d certificates, %ld Bytes, last update %s",
                      veri_counter, veri_stat.st_size, ctime(&veri_stat.st_mtime));
    if (strcmp(cab_type, "pc") == 0)
      fprintf(cgiOut, "%s certificate bundle - %d certificates, %d Bytes, uploaded on %s",
                      cab_name, veri_counter, veri_fsize, ctime(&now));
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=\"2\">");
    fprintf(cgiOut, "<input type=\"button\" value=\"Print Page\" ");
    fprintf(cgiOut, "onclick=\"print(); return false;\" />\n");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</tr>\n");

    fprintf(cgiOut, "</table>\n");
    fprintf(cgiOut, "<p></p>\n");

    /* ---------------------------------------------------------- *
     * If the remote server provided signing certs, offer to show *
     * ---------------------------------------------------------- */
    if(rem_chain_count > 1) {
      X509 *stack_item = NULL;
      int i;

      fprintf(cgiOut, "<div id=\"rem_chain\" style=\"display: none\">\n");
      fprintf(cgiOut, "<h3>Server-provided Certificate Chain</h3>\n");
      fprintf(cgiOut, "<hr />\n");
      fprintf(cgiOut, "<p>\n");
      fprintf(cgiOut, "A server certificate is often signed by an intermediate certificate authority.\n");
      fprintf(cgiOut, "Particularly commercial certificate authorities operate through intermediates,\n");
      fprintf(cgiOut, "instead of signing directly with the root certificate.\n");
      fprintf(cgiOut, "These intermediate CA certificates, although <b>required</b> to validate the certificate chain,\n");
      fprintf(cgiOut, "are typically <b>not</b> in the client application’s list of trusted CAs.\n");
      fprintf(cgiOut, "Client applications (i.e. browsers) only have limited root certificate lists\n");
      fprintf(cgiOut, " with approved commercial CA's.\n");
      fprintf(cgiOut, " To overcome this gap, the TLS/SSL protocol can be configured to let the server\n");
      fprintf(cgiOut, "  provide the signing certificate(s) (incl. intermediates) to the connecting client.\n");
      fprintf(cgiOut, "Below is the list of signing certificates that have been received from this server:\n");
      fprintf(cgiOut, "</p>\n");

      for (i = 1; i < rem_chain_count; i++) {
        stack_item = sk_X509_value(rem_chain, i);
        display_cert(stack_item, "Server-provided Signing", "rem_chain", i);

        fprintf(cgiOut, "<p></p>\n");
      }
      fprintf(cgiOut, "</div>\n");
    }

    /* ------------------------------------------------------------------- *
     * If validation is OK, show all certs in the validated results stack  *
     * ------------------------------------------------------------------- */
    if(ret == 1) {
      X509 *stack_item = NULL;
      int i;
      int res_stack_count = sk_X509_num(res_stack);

      fprintf(cgiOut, "<h3>Webcert-validated Certificate Chain</h3>\n");
      fprintf(cgiOut, "<hr />\n");
      fprintf(cgiOut, "<p>\n");
      fprintf(cgiOut, "WebCert successfully validated the certificate.\n");
      fprintf(cgiOut, "Below are the details of all %d certificates",  res_stack_count);
      fprintf(cgiOut, " involved in building the hierarchy of trust:\n");
      fprintf(cgiOut, "</p>\n");

      for (i = 0; i < res_stack_count; i++) {
        stack_item = sk_X509_value(res_stack, i);

        if(i == 0 && i <  res_stack_count-1) display_cert(stack_item, "Server/System/Application", "wct_chain", i);
        if(i >  0 && i <  res_stack_count-1) display_cert(stack_item, "Intermediate", "wct_chain", i);
        if(i == 0 && i == res_stack_count-1) display_cert(stack_item, "Self-Signed or Root", "wct_chain", i);
        if(i >  0 && i == res_stack_count-1) display_cert(stack_item, "Root", "wct_chain", i);

        fprintf(cgiOut, "<p></p>");
      }
    }
    else {
    /* ---------------------------------------------------------- *
     * If failure, show the cert that failed                      *
     * ---------------------------------------------------------- */
      fprintf(cgiOut, "<h3>Certificate Validation Failure Details</h3>\n");
      fprintf(cgiOut, "<hr />\n");
      fprintf(cgiOut, "<p>\n");
      fprintf(cgiOut, "WebCert failed to validate this certificate:\n");
      fprintf(cgiOut, "</p>\n");

      display_cert(cert, "Failed", "wct_chain", 0);
    }
  }
  
/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/
  pagefoot();
  return(0);
}

/* ---------------------------------------------------------- *
 * X509_load_ca_file() loads a CA file into a mem BIO using   *
 * (BIO_read_filename(), PEM_X509_INFO_read_bio() puts them   *
 * in a stack, which is then to be added to a store or CTX.   *
 * ---------------------------------------------------------- */
STACK_OF(X509_INFO) *X509_load_ca_file(int *cert_count,
                      struct stat *fstat, const char *file) {
  STACK_OF(X509_INFO) *st = NULL;
  BIO *inbio=NULL;

  /* ---------------------------------------------------------- *
   * complain if we got an empty filename                       *
   * ---------------------------------------------------------- */
  if (file == NULL)
    BIO_printf(outbio, "Error receiving a valid CA bundle file name.\n");

  /* ---------------------------------------------------------- *
   * get file status data                                       *
   * ---------------------------------------------------------- */
  if (stat(file, fstat) != 0)
    BIO_printf(outbio, "Error cannot stat CA cert bundle file.\n");

  /* ---------------------------------------------------------- *
   * complain if the file is empty (0 bytes)                    *
   * ---------------------------------------------------------- */
  if(fstat->st_size == 0)
    BIO_printf(outbio, "Error CA cert bundle file size is zero bytes.\n");

  inbio=BIO_new(BIO_s_file_internal());

  /* ---------------------------------------------------------- *
   * check if we can open the file for reading                  *
   * ---------------------------------------------------------- */
  if ((inbio == NULL) || (BIO_read_filename(inbio, file) <= 0))
    BIO_printf(outbio, "Error loading CA cert bundle file into memory.\n");

  /* ---------------------------------------------------------- *
   * read all certificates from file                            *
   * ---------------------------------------------------------- */
  if (! (st = PEM_X509_INFO_read_bio(inbio, NULL, NULL, NULL)))
    BIO_printf(outbio, "Error reading CA certs from BIO.\n");

  /* ---------------------------------------------------------- *
   * get the number of certs that are now on the stack          *
   * ---------------------------------------------------------- */
  *cert_count = sk_X509_INFO_num(st);

  /* ---------------------------------------------------------- *
   * return the STACK_OF(X509_INFO) pointer, or NULL            *
   * ---------------------------------------------------------- */
  if (cert_count > 0) return st;
  else return NULL;
}

/* ---------------------------------------------------------- *
 * verify_mem_store() puts the CA info stack into a store     *
 * struct, which is then passed to the CTX during the init.   *
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_mem_store(STACK_OF(X509_INFO) *st) {
  X509_STORE         *store = NULL;
  X509_STORE_CTX       *ctx = NULL;
  X509_INFO      *list_item = NULL;
  int cert_count            = 0;
  int i                     = 0;

  /* ---------------------------------------------------------- *
   * Initialize the global certificate validation store object. *
   * ---------------------------------------------------------- */
  if (!(store=X509_STORE_new()))
     BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

  /* ---------------------------------------------------------- *
   * Create the context structure for the validation operation. *
   * ---------------------------------------------------------- */
  ctx = X509_STORE_CTX_new();

  /* ---------------------------------------------------------- *
   * Get the number of certs on the stack                       *
   * ---------------------------------------------------------- */
  cert_count = sk_X509_INFO_num(st);

  /* ---------------------------------------------------------- *
   * Complain if there is no cert                               *
   * ---------------------------------------------------------- */
  if (! cert_count > 0)
    BIO_printf(outbio, "Error no certs on stack.\n");

  /* ---------------------------------------------------------- *
   * Cycle through all info stack items, extract the X509 cert  *
   * and put it into the X509_STORE called store.               *
   * ---------------------------------------------------------- */
  for (i = 0; i < cert_count; i++) {
    list_item = sk_X509_INFO_value(st, i);
    X509_STORE_add_cert(store, list_item->x509);
  }

  /* ---------------------------------------------------------- *
   * Initialize the ctx structure for a verification operation: *
   * Set the trusted cert store, the unvalidated cert, and any  *
   * potential certs that could be needed (here we set it NULL) *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  return ctx;
}


/* ---------------------------------------------------------- *
 * file_select() is a filter function for scandir(), helping  *
 * to return only files having the global string file_prefix  *
 * ---------------------------------------------------------- */
int file_select(const struct dirent *entry) {
  /* skip "." and ".." directory entries */
  if(entry->d_name[0]=='.') return 0;

  /* Check for the file prefix provided */
  if(strstr(entry->d_name, file_prefix) != NULL) return 1;

  return 0;
}

/* ---------------------------------------------------------- *
 * get_latest_ca_bundle() checks for the most recent file     *
 * containing  MOZI_PREFIX or VERI_PREFIX in CABUNDLEDIR,     *
 * puts this file path to the string arg & ret the # of files *
 * ---------------------------------------------------------- */
int get_latest_ca_bundle(char bundlestr[]) {
  int files_found = 0;
  struct dirent **namelist;

  files_found = scandir(CABUNDLEDIR, &namelist, file_select, alphasort);
  /* pick up the latest file we can find */
  if(files_found) snprintf(bundlestr, CB_STRLEN, "%s/%s", 
             CABUNDLEDIR, namelist[files_found-1]->d_name);

  return files_found;
}

/* ---------------------------------------------------------- * 
 * create_socket() creates the socket & TCP-connect to server * 
 * ---------------------------------------------------------- */
int create_socket(char url_str[]) {
  int sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char   srvname[80] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  struct sockaddr_in dest_addr;
  struct servent *service;

  /* Sometimes, a pasted string as a trailing space */
  if(url_str[strlen(url_str)-1] == ' ')
    url_str[strlen(url_str)-1] = '\0';

  /* Remove the final / from url_str, if given */
  if(url_str[strlen(url_str)-1] == '/')
    url_str[strlen(url_str)-1] = '\0';

  /* the first : ends the protocol string, i.e. http */
  strncpy(srvname, url_str, (strchr(url_str, ':')-url_str));

  /* the hostname starts after the "://" part */
  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

  /* if the hostname contains :, we got a port number */
  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
    port = atoi(portnum);
  }
  else {
    /* if we dont get a specific port number, we use the service */
    if ( (service = getservbyname(srvname, "tcp")) == NULL ) {
      snprintf(error_str, sizeof(error_str), "Cannot resolve service [%s]",  srvname);
      int_error(error_str);
    }
    port = ntohs(service->s_port);
  }

  if ( (host = gethostbyname(hostname)) == NULL ) {
    snprintf(error_str, sizeof(error_str), "Cannot resolve host [%s]",  hostname);
    int_error(error_str);
    abort();
  }

  /* create the basic TCP socket */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  //dest_addr.sin_addr.s_addr=inet_addr(ip);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  /* Zeroing the rest of the struct */
  memset(&(dest_addr.sin_zero), '\0', 8);

  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  /* Try to make the host connect here */
  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    snprintf(error_str, sizeof(error_str),
             "Cannot connect to host %s [%s] on port %d.",
             hostname, tmp_ptr, port);
    int_error(error_str);
  }

  return sockfd;
}

/* ---------------------------------------------------------- *
 * X509_signature_dump() converts binary signature data into  *
 * hex bytes, separated with : and a newline after 54 chars.  *
 * (2 chars + 1 ':' = 3 chars, 3 chars * 18 = 54)             *
 * ---------------------------------------------------------- */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent) {
  const unsigned char *s;
  int i, n;

  n=sig->length;
  s=sig->data;
  for (i=0; i<n; i++) {
    if ((i%21) == 0) {
      if (i != 0 && BIO_write(bp,"\n",1) <= 0) return 0;
      if (BIO_indent(bp, indent, indent) <= 0) return 0;
    }
    if (BIO_printf(bp,"%02x%s",s[i],
      ((i+1) == n)?"":":") <= 0) return 0;
  }

  if (BIO_write(bp,"\n",1) != 1) return 0;

  return 1;
}

/* ---------------------------------------------------------- *
 * OpenSSL seems to lack a few OID's used for EV certificates *
 * ---------------------------------------------------------- */
void add_missing_ev_oids() {
  /* --------------------------------------------------------- *
   * OBJ_create():                                             *
   * First field is the OID, which will be converted to DER    *
   * encoding. Next are the long and short description of      *
   * this OID. The descriptions will not be included as the    *
   * extension identifier, but the DER encoding of the OID.    *
   * --------------------------------------------------------- */
  OBJ_create("1.3.6.1.4.1.311.60.2.1.1",
             "jurisdiction Of Incorporation LocalityName",
             "jurisdiction Of Incorporation LocalityName");

  OBJ_create("1.3.6.1.4.1.311.60.2.1.2",
             "jurisdiction Of Incorporation StateOrProvinceName",
             "jurisdiction Of Incorporation StateOrProvinceName");

  OBJ_create("1.3.6.1.4.1.311.60.2.1.3",
             "jurisdiction Of Incorporation CountryName",
             "jurisdiction Of Incorporation CountryName");

  /* Logo Type definition, see http://www.ietf.org/rfc/rfc3709 */
  OBJ_create("1.3.6.1.5.5.7.1.12",
             "id-pe-logotype",
             "id-pe-logotype");
}

/* ---------------------------------------------------------- *
 * display_cert() shows certificate details in a HTML table.  *
 * --> *ct is the certificate to display                      *
 * --> ct_type[] is the type (Root, Intermediate, Server...)  *
 * --> chain_type[] together with int level creates a unique  *
 * identifier for use with the Javascript Show/Hide function  *
 * ---------------------------------------------------------- */
void display_cert(X509 *ct, char ct_type[], char chain_type[], int level) {
  X509_NAME       *certname = NULL;
  X509_NAME     *issuername = NULL;
  X509_CINF       *cert_inf = NULL;
  STACK_OF(X509_EXTENSION) *ext_list;
  const EVP_MD *fprint_type = NULL;
  unsigned char fprint[EVP_MAX_MD_SIZE];
  ASN1_INTEGER *asn1_serial = 0;
             EVP_PKEY *pkey = NULL;
  unsigned int   thumb_size = 0;
  ASN1_STRING     *asn1_sig = NULL;
  X509_ALGOR      *sig_type = NULL;
  size_t          sig_bytes = 0;
  char   sig_type_str[1024] = "";
  long cert_version;
  int i;

  /* ---------------------------------------------------------- *
   * extract and print various certificate information          *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(ct);

  issuername = X509_NAME_new();
  issuername = X509_get_issuer_name(ct);

  asn1_serial = X509_get_serialNumber(ct);

  cert_version = (X509_get_version(ct)+1);

  pkey = X509_get_pubkey(ct);

  fprint_type = EVP_sha256();
  if (!X509_digest(ct, fprint_type, fprint, &thumb_size))
    int_error("Error creating the certificate fingerprint.");

  /* ---------------------------------------------------------- *
   * Extract the certificate's extensions                       *
   * ---------------------------------------------------------- */
  cert_inf = ct->cert_info;
  ext_list = cert_inf->extensions;

  /* ---------------------------------------------------------- *
   * Extract the certificate's signature data.                  *
   * ---------------------------------------------------------- */
  sig_type = ct->sig_alg;
  asn1_sig = ct->signature;
  sig_bytes = asn1_sig->length;
  OBJ_obj2txt(sig_type_str, sizeof(sig_type_str), sig_type->algorithm, 0);

  fprintf(cgiOut, "<table width=\"100%%\">\n");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">");
  fprintf(cgiOut, "%s Certificate Information", ct_type);
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th width=\"70px\">Version:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert subject here */
  fprintf(cgiOut, "%ld", cert_version);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th width=\"70px\">Subject:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert subject here */
  X509_NAME_print_ex_fp(cgiOut, certname, 0,
         ASN1_STRFLGS_UTF8_CONVERT|XN_FLAG_SEP_CPLUS_SPC);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Serial:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert serial here */
  i2a_ASN1_INTEGER(outbio, asn1_serial);
  BIO_puts(outbio,"\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Issuer:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the cert issuer here */
  X509_NAME_print_ex_fp(cgiOut, issuername, 0, 0);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Thumbprint:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the thumbprint here */
  BIO_printf(outbio, OBJ_nid2sn(EVP_MD_type(fprint_type)));
  BIO_printf(outbio,": ");
  for (i=0; i<thumb_size; ++i) BIO_printf(outbio, "%02x ", fprint[i]);
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Validity:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td>");
  /* display the start and end date here */
  fprintf(cgiOut, "Start Date: ");
  if (!ASN1_TIME_print(outbio ,X509_get_notBefore(ct)))
    fprintf(cgiOut, "***n/a***");
  fprintf(cgiOut, " &nbsp; End Date: ");
  if (!ASN1_TIME_print(outbio ,X509_get_notAfter(ct)))
    fprintf(cgiOut, "***n/a***");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Extensions:");
  fprintf(cgiOut, "</th>\n");
  if (sk_X509_EXTENSION_num(ext_list) <= 0)
    fprintf(cgiOut, "<td>No extensions available");
  else {
    fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
    fprintf(cgiOut, "%d Extensions\n", sk_X509_EXTENSION_num(ext_list));
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certext_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Extension Details</a>");
  /* display the cert extension list here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"certext_%s%d\"  style=\"display: none\"><pre>", chain_type, level);
  for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext;

    ext = sk_X509_EXTENSION_value(ext_list, i);

    obj = X509_EXTENSION_get_object(ext);
    fprintf(cgiOut, "Object %.2d: ", i);
    i2a_ASN1_OBJECT(outbio, obj);
    fprintf(cgiOut, "\n");

    if (!X509V3_EXT_print(outbio, ext, 0, 2)) {
    /* Some extensions (i.e. LogoType) have no handling    *
     * defined, we need to print their content as hex data */
      fprintf(cgiOut, "%*s", 2, "");
      M_ASN1_OCTET_STRING_print(outbio, ext->value);
    }
    fprintf(cgiOut, "\n");

    if (i<sk_X509_EXTENSION_num(ext_list)-1)
      fprintf(cgiOut, "\n");
  }

  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  }
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Public Key:");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  /* display the key type and size here */
  if (pkey) {
    EC_KEY *myecc = NULL;
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        fprintf(stdout, "%d bit RSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        fprintf(stdout, "%d bit DSA Key", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_EC:
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        fprintf(stdout, "%d bit ECC Key, type %s", EVP_PKEY_bits(pkey),
                            OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
        break;
      default:
        fprintf(stdout, "%d bit non-RSA/DSA Key", EVP_PKEY_bits(pkey));
        break;
    }
  }

  fprintf(cgiOut, " <a href=\"javascript:elementHideShow('pubkey_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Public Key Data</a>");
  /* display the public key data in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"pubkey_%s%d\" style=\"display: none\"><pre>", chain_type, level);
  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Signature:");
  fprintf(cgiOut, "</th>\n");
  if (strstr(sig_type_str, "Md5") || strstr(sig_type_str, "md5"))
    fprintf(cgiOut, "<td bgcolor=\"#cf0f0f\">");
  else fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "%s, Length: %d Bytes\n", sig_type_str, (int) sig_bytes);
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certsig_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Signature Data</a>");
  /* display the cert signature in hex byte format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"certsig_%s%d\"  style=\"display: none\"><pre>", chain_type, level);
  if (X509_signature_dump(outbio, asn1_sig, 0) != 1)
    BIO_printf(outbio, "Error printing the signature data\n"); 
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th>Cert Data: ");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<td bgcolor=\"#cfcfcf\">");
  fprintf(cgiOut, "<a href=\"javascript:elementHideShow('certpem_%s%d');\">\n", chain_type, level);
  fprintf(cgiOut, "Expand or Hide Certificate PEM Data</a>");
  /* display the cert content in PEM format here */
  fprintf(cgiOut, "<div class=\"showpem\" id=\"certpem_%s%d\"  style=\"display: none\"><pre>",chain_type, level);
  PEM_write_bio_X509(outbio, ct);
  fprintf(cgiOut, "</pre></div>\n");
  fprintf(cgiOut, "</td>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"2\">&nbsp;");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</tr>\n");

  fprintf(cgiOut, "</table>\n");
}
