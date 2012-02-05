/* testserial.c			25/06/2005 frank4dd	     */
/* test example for management of certificate serial numbers */

#include "openssl/asn1.h"
#include "openssl/bn.h"
#include "webcert.h"

#define MAXTESTS	3

int main() {

BIGNUM	*ser;
char    *dec;
ASN1_INTEGER *bs = NULL;
int	i;


  for(i=0; i<MAXTESTS; i++) {
    ser = load_serial(SERIALFILE, 1, NULL);
    dec = BN_bn2dec(ser);
  
    printf("loaded serial: %s\n", dec);
  
    if (!BN_add_word(ser,1)) printf("error serial increment\n");
  
    dec = BN_bn2dec(ser);
  
    printf("incremented serial: %s\n", dec);
  
    save_serial(SERIALFILE, 0, ser, &bs);
  
    ser = load_serial(SERIALFILE, 1, NULL);
    dec = BN_bn2dec(ser);
  
    printf("written serial: %s\n", dec);
    printf("-------------------------\n");
  }
  return i;
}
