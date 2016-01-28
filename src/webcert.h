/* ---------------------------------------------------------------------------*
 * file:        webcert.h                                                     *
 * purpose:     provide standard definitions accross cgi's                    *
 * author:      03/04/2004 Frank4DD                                           *
 * ---------------------------------------------------------------------------*/

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "openssl/asn1.h"
#include "openssl/bn.h"

/*********** the main URL where the webcert application resides ***************/
#define HOMELINK	"/sw/webcert/"
/*********** the application entry URL which is seen first ********************/
#define REQLINK		"/sw/webcert/cgi-bin/certrequest.cgi"
/*********** where is the ca certificate .pem file ****************************/
#define CACERT 		"/srv/app/webCA/cacert.pem"
/*********** where is the ca's private key file *******************************/
#define CAKEY           "/srv/app/webCA/private/cakey.pem"
/*********** The password for the ca's private key ****************************/
#define PASS            "mypassword"
/*********** The directory where the generated certificates are stored ********/
#define CACERTSTORE	"/srv/app/webCA/certs"
/*********** The directory for the external, trusted CA bundles files *********/
#define CABUNDLEDIR	"/srv/app/webCA/ca-bundles"
/*********** The directory to write the exported certificates into ************/
#define CERTEXPORTDIR   "/srv/www/std-root/fm4dd.com/sw/webcert/export"
/*********** The export directory URL to download the certificates from *******/
#define CERTEXPORTURL   "/sw/webcert/export"
/*********** where the ca's serial file is ************************************/
#define SERIALFILE      "/srv/app/webCA/serial"
/*********** certificate lifetime *********************************************/
#define DAYS_VALID      1095
#define YEARS_VALID     3

/* For the public demo, I enforce adding the source IP to the certificate CN */
/* For internal use, you could take it out. */
/* #define FORCE_SOURCE_IP_INCLUSION	TRUE */

/* On most 32bit systems, the time calculation has the year-2038 bug, when  */
/* the signed integer rolls over to the year 1901. Here is the protection.  */ 
#define TIME_PROTECTION  TRUE

/***************** *********************************** ************************/
/***************** no changes required below this line ************************/
/***************** *********************************** ************************/

#define CONTACT_EMAIL	"support@fm4dd.com"
#define SW_VERSION	"WebCert v1.7.8 (01/09/2016)"

/*********** html code template for populating the sidebar  *******************/
#define SIDEBAR_TEMPL	"../sidebar-template.htm" /* optional */
/*********** html code template for populating the help data  *****************/
#define HELP_TEMPL	"../help-template.htm" /* mandatory */
/*********** html code template for populating the policy text  ***************/
#define POLICY_TEMPL	"../policy-template.htm" /* mandatory */
/****** html code template for adding code or scripts into the footer *********/
#define FOOTER_TEMPL	"../footer-template.htm" /* optional */

/****** Define WebCert's default signing algorithm for certs and CSRs *********/
#define DEF_SIGN_ALG_RSA    EVP_sha256()
#define DEF_SIGN_ALG_DSA    EVP_dss1()

#define REQLEN	       32768 /* Max length of a certificate request in bytes.*/
                             /* Often not bigger then 817 bytes with a 1024  */
			     /* bit RSA key. Increase size for bigger keys   */
			     /* and when a lot of attributes are generated.  */

#define KEYLEN         32768 /* this is the max length of a private key in   */
                             /* PEM format used for the PKCS12 cert bundle   */
                             /* generation. 32KByte should cover large keys. */

#define CALISTLEN    4194304 /* this is the max length of a CA list file in  */
                             /* PEM format used for the PKCS12 cert bundle   */
                             /* generation. (4MB)                            */

#define P12PASSLEN      41   /* this is the max length for the password used */
                             /* as protection for the PKCS12 cert bundle.    */

#define MAXCERTDISPLAY	8    /* # of certs that will be shown in one webpage */

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)

/* ---------------------------------------------------------- *
 * Shared function declarations                               *
 * ---------------------------------------------------------- */
void pagehead(char *title);
void pagefoot();
void handle_error(const char *file, int lineno, const char *msg);

BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(char *serialfile, char *suffix, BIGNUM *serial, ASN1_INTEGER **retai);

/* ---------------------------------------------------------- *
 * This function adds missing OID's to the internal structure *
 * ---------------------------------------------------------- */
void add_missing_ev_oids();

/* ---------------------------------------------------------- *
 * display_xxx() generates xxx detail output in a HTML table. *
 * ---------------------------------------------------------- */
void display_cert(X509 *cert, char ct_type[], char chain_type[], int level);
void display_signing(X509_REQ *);
void display_csr(X509_REQ *);
void display_key(EVP_PKEY *);

/* ---------------------------------------------------------- *
 * xxx_validate() does a basic check of xxx PEM format input  *
 * ---------------------------------------------------------- */
void key_validate(char *);
void csr_validate(char *);

void keycreate_input();

/****************************** end webcert.h *********************************/
