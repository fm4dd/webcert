/* -------------------------------------------------------------------------- *
 * file:         about.c                                                      *
 * purpose:      display the statement in the about.txt file                  *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <cgic.h>
#include "webcert.h"

int cgiMain() {

  int ret;
  FILE *fp;
  static char title[] = "About";

  if (! (fp = fopen("about.txt", "r")))
     int_error("Error can't open about.txt");

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
