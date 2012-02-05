/* tests the correct ascii - to - hex conversion to create  *
 * a sorting function as replacent for alphasort in scandir *
 *                                                          * 
 * cert files are saved with the serial number in hex used  * 
 * as the filename. When 255 (FF) is reached, the next two  *
 * digits are added by the function BN_bn2hex().            *
 * Alphasort missplaces files because it doesnt care about  *
 * the length.                                              */

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#define CACERTSTORE "/home/webCA/certs"

int hexsort(const void *test1, const void *test2) {
  char *endptr;
  printf("1: %s\n", (*(const struct dirent **)test1)->d_name);
  return (strtol((*(const struct dirent **)test1)->d_name, &endptr, 16)
         - strtol((*(const struct dirent **)test2)->d_name, &endptr, 16));
}

int file_select(const struct dirent *entry) {

  /* check for "." and ".." directory entries */
  if(entry->d_name[0]=='.') return 0;

  /* Check for <id>.pem file name extensions */
  if(strstr(entry->d_name, ".pem") != NULL) return 1;
  else return 0;
}

int main(void) { 
  static void *test2= "0C6B.pem";
  static void *test1= "0C6D.pem";
  char *endptr;
  long int result1 = 0;
  long int result2 = 0;
  int certcounter,i = 0;


  struct dirent **certstore_files;

  result1=strtol(test1, &endptr, 16);
  result2=strtol(test2, &endptr, 16);
  
    printf("1. Convert string [%s] to int [%d] format [%.3d].\n",
                  test1, result1, result1);

    printf("2. Convert string [%s] to int [%d] format [%.3d].\n",
                  test2, result2, result2);

  printf("return result is: [%d]\n", 
  (strtol(test1, &endptr, 16) - strtol(test2, &endptr, 16)));

  certcounter = scandir(CACERTSTORE, &certstore_files, file_select, hexsort);
  printf("certs found: [%d]\n", certcounter);
  for(i=0; i< certcounter; i++) {
    printf("file is: [%s]\n", certstore_files[i]->d_name);
  }
}
