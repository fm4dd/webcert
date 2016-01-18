/* -------------------------------------------------------------------------- *
 * file:         capolicy.c                                                   *
 * purpose:      display CA policy in capolicy.txt file                       *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <cgic.h>
#include "webcert.h"

int cgiMain() {
  int ret;
  FILE *fp;
  static char title[] = "CA Policy";

  if (! (fp = fopen(POLICY_TEMPL, "r")))
     int_error("Error can't open the policy file");

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/
   pagehead(title);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/
   for(;;) {
      ret = getc(fp);
      if(ret == EOF) break;
      fprintf(cgiOut, "%c", ret);
   }

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/
   pagefoot();
   fclose(fp);
   return(0);
}
