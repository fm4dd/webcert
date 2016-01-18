/* -------------------------------------------------------------------------- *
 * file:         help.c                                                       *
 * purpose:      display webcert help in help.txt file                        *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <cgic.h>
#include "webcert.h"

int cgiMain() {
  int ret;
  FILE *fp;
  static char title[] = "Help and additional Information";

  if (! (fp = fopen(HELP_TEMPL, "r")))
     int_error("Error cant open help file");

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
   pagefoot();
   fclose(fp);
   return(0);
}
