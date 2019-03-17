/* ---------------------------------------------------------------------------*
 * file:        webcert.h                                                     *
 * purpose:     provide standard definitions accross cgi's                    *
 * author:      03/04/2004 Frank4DD                                           *
 * ---------------------------------------------------------------------------*/

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "openssl/asn1.h"
#include "openssl/bn.h"
#include <openssl/txt_db.h>

/*********** the main URL where the webcert application resides ***************/
#define HOMELINK	"/webcert/"
/*********** the application entry URL which is seen first ********************/
#define REQLINK		"/webcert/cgi-bin/certrequest.cgi"
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
#define CERTEXPORTDIR   "/srv/www/webcert/export"
/*********** The export directory URL to download the certificates from *******/
#define CERTEXPORTURL   "/export"
/*********** where the ca's serial file is ************************************/
#define SERIALFILE      "/srv/app/webCA/serial"
/*********** certificate lifetime *********************************************/
#define DAYS_VALID      1095
#define YEARS_VALID     3

/*********** CRL Handling: The link to webcerts crl ***************************/
#define CRLURI		"URI:http://fm4dd.com/sw/webcert/webcert.crl"
#define CRLFILE		"/srv/www/webcert/webcert.crl"
#define REVOKEY         "/srv/app/webCA/private/revocation-pub.pem"
/*********** we store the list of revoked certs in index.txt ******************/
#define INDEXFILE       "/srv/app/webCA/index.txt"
/*********** we store the CRL sequence number in file crlnumber ***************/
#define CRLSEQNUM       "/srv/app/webCA/crlnumber"
/*********** we store the CRL default expiration days and hours ***************/
#define CRLEXPDAYS	30
#define CRLEXPHRS	0


/* For the public demo, I enforce adding the source IP to the certificate CN */
/* For internal use, you could take it out. */
/* #define FORCE_SOURCE_IP_INCLUSION	TRUE */

/* On most 32bit systems, the time calculation has the year-2038 bug, when  */
/* the signed integer rolls over to the year 1901. Here is the protection.  */ 
/* webcert demo site runs on a unaffected 64bit system, it defaults to off. */
//#define TIME_PROTECTION  TRUE

/***************** *********************************** ************************/
/***************** no changes required below this line ************************/
/***************** *********************************** ************************/

#define CONTACT_EMAIL	"support@fm4dd.com"
#define SW_VERSION	"WebCert v1.8.0 (03/17/2019)"

/*********** html code template for populating the sidebar  *******************/
#define SIDEBAR_TEMPL	"../sidebar-template.htm" /* optional */
/*********** html code template for populating the index  *********************/
#define INDEX_TEMPL	"../index-template.htm" /* mandatory */
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


# define DB_type         0      /* 'R','E','V' or 'S' */
# define DB_exp_date     1      /* expiration tstamp  */
# define DB_rev_date     2      /* revocation tstamp  */
# define DB_serial       3      /* index - unique     */
# define DB_file         4      /* currently unused   */
# define DB_name         5      /* index - unique when active and not disabled */
# define DB_NUMBER       6      /* Number of DB fields */

# define DB_TYPE_REV     'R'    /* Revoked   */
# define DB_TYPE_EXP     'E'    /* Expired   */
# define DB_TYPE_VAL     'V'    /* Valid     */
# define DB_TYPE_SUSP    'S'    /* Suspended */

/* Additional revocation information types per OpenSSL apps/ca.c */
typedef enum {
    REV_VALID             = -1, /* Valid (not-revoked) status        */
    REV_NONE              = 0,  /* No additional information         */
    REV_CRL_REASON        = 1,  /* Value is CRL reason code          */
    REV_HOLD              = 2,  /* Value is hold instruction         */
    REV_KEY_COMPROMISE    = 3,  /* Value is cert key compromise time */
    REV_CA_COMPROMISE     = 4   /* Value is CA key compromise time   */
} REVINFO_TYPE;

typedef struct db_attr_st { int unique_subject; } DB_ATTR;
typedef struct ca_db_st { DB_ATTR attributes; TXT_DB *db; } CA_DB;

/* ---------------------------------------------------------- *
 * Shared function declarations                               *
 * ---------------------------------------------------------- */
void pagehead(char *title);
void pagefoot();
void handle_error(const char *file, int lineno, const char *msg);

/* ---------------------------------------------------------- *
 * These functions are local copies from openssl apps/apps.c  *
 * ---------------------------------------------------------- */
BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(char *serialfile, char *suffix, BIGNUM *serial, ASN1_INTEGER **retai);
int rotate_serial(const char *serialfile, const char *new_suffix, const char *old_suffix);
CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr);
int save_index(const char *dbfile, CA_DB *db);
int make_revoked(X509_REVOKED *rev, const char *str);

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
void display_crl(X509_CRL *);
void display_crl_top(X509_CRL *crl, int count);

/* ---------------------------------------------------------- *
 * xxx_validate_PEM(): a basic check of xxx PEM format input  *
 * ---------------------------------------------------------- */
void key_validate_PEM(char *);
void csr_validate_PEM(char *);

/* ---------------------------------------------------------- *
 * cgi_load_xxxfile() load a PEM file to corresponding struct *
 * ---------------------------------------------------------- */
X509 * cgi_load_certfile(char *);
X509_REQ * cgi_load_csrfile(char *);
EVP_PKEY * cgi_load_keyfile(char *);
X509_CRL * cgi_load_crlfile(char *);

/* ---------------------------------------------------------- *
 * cgi_load_xxxform() load a PEM form to corresponding struct *
 * ---------------------------------------------------------- */
X509_REQ * cgi_load_csrform(char *);

/* ---------------------------------------------------------- *
 * cgi_gencrl() creates the CRL file from the CA's index db   *
 * ---------------------------------------------------------- */
int cgi_gencrl(char *crlfile);

void keycreate_input();

char error_str[4096];
/****************************** end webcert.h *********************************/
