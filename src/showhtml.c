/* -------------------------------------------------------------------------- *
 * file:         showhtml.c                                                   *
 * purpose:      display html template files for help, CA policy, and index   *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "webcert.h"

int cgiMain() {
  int ret;
  FILE *fp = NULL;
  static char templ[41];
  static char title[41];

  if (! (cgiFormString("templ", templ, sizeof(templ)) == cgiFormSuccess))
    int_error("Error getting >templ< from calling URL");

  if (strcmp(templ, "help") == 0) {
    snprintf(title, sizeof(title), "%s", "Help and additional Information");

    if (! (fp = fopen(HELP_TEMPL, "r")))
      int_error("Error can't open help file");
  }

  else if (strcmp(templ, "index") == 0) {
    snprintf(title, sizeof(title), "%s", "Index");

    if (! (fp = fopen(INDEX_TEMPL, "r")))
      int_error("Error can't open index file");
  }

  else if (strcmp(templ, "policy") == 0) {
    snprintf(title, sizeof(title), "%s", "CA Policy");

    if (! (fp = fopen(POLICY_TEMPL, "r")))
      int_error("Error can't open policy file");
  }

  else  {
    int_error("Error unknown template file");
  }

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/
  pagehead(title);

  for(;;) {
    ret = getc(fp);
    if(ret == EOF) break;
    fprintf(cgiOut, "%c", ret);
  }
  pagefoot();
  fclose(fp);
  return 0;
}
