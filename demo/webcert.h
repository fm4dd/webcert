/* ---------------------------------------------------------------------------*
 * file:        webcert.h                                                     *
 * purpose:     provide standard definitions accross cgi's                    *
 * author:      03/04/2004 Frank4DD                                           *
 * ---------------------------------------------------------------------------*/

/*********** adjust the URL and path to your cert directory below *************/
#define HOMELINK	"/webcert/"
#define REQLINK		"/webcert/cgi-bin/certrequest.cgi"
#define CACERT 		"/home/webCA/cacert.pem"
#define CACERTSTORE	"/home/webCA/certs/"
#define SERIALFILE      "/home/webCA/serial"

#define CONTACT_EMAIL	"support@frank4dd.com"
#define SW_VERSION	"WebCert v1.2.2 (25/06/2005)"

/***************** no changes required below this line ************************/

#define REQLEN		2048 /* Max length of a certificate request in bytes.*/
                             /* Often not bigger then 817 bytes with a 1024  */
			     /* bit RSA key, size increases for bigger keys  */
			     /* and when a lot of attributes are generated.  */

#define MAXCERTDISPLAY	10   /* # of certs that will be shown in one webpage */

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)

void pagehead(char *title);
void handle_error(const char *file, int lineno, const char *msg);
ASN1_INTEGER *x509_load_serial(char *CAfile, char *serialfile, int create);
BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(char *serialfile, char *suffix, BIGNUM *serial, ASN1_INTEGER **retai);

/****************************** end webcert.h *********************************/
