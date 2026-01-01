/* -------------------------------------------------------------------------- *
 * file:         pagefoot.c                                                   *
 * purpose:      provides a standard page footer across all cgi's             *
 * ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "webcert.h"

void pagefoot() {

  int ret;
  FILE *fp;
  char hostport[72] = "[unknown] port [none]";
 
  if(strlen(cgiServerName) != 0) {
     strcpy(hostport, cgiServerName);
     strcat(hostport, " port ");
     strcat(hostport, cgiServerPort);
  }

  fprintf(cgiOut, "</div>\n");

  fprintf(cgiOut, "<div id=\"sidecontent\">\n");
  if ((fp = fopen(SIDEBAR_TEMPL, "r"))) {
     for(;;) {
        ret = getc(fp);
        if(ret == EOF) break;
        fprintf(cgiOut, "%c", ret);
    }
  }
  fprintf(cgiOut, "</div>\n");

  fprintf(cgiOut, "<div id=\"footer\">\n");
  fprintf(cgiOut, "<span class=\"left\">&copy; %s by <a href=\"https://fm4dd.com/\">Frank4DD</a>.</span>\n", SW_VERSION);
  fprintf(cgiOut, "<span class=\"right\">");
  fprintf(cgiOut, "Generated on: %s", hostport);
  fprintf(cgiOut, " for ");
  if (strlen(cgiRemoteUser) != 0) fprintf(cgiOut, "%s", cgiRemoteUser);
  if (strlen(cgiRemoteAddr) != 0) fprintf(cgiOut, "%s", cgiRemoteAddr);
  else fprintf(cgiOut, "%s", "[unknown]");
  fprintf(cgiOut, "</span>\n");
  fprintf(cgiOut, "</div>\n");

  fprintf(cgiOut, "</div>\n");
  fprintf(cgiOut, "</body>\n");
  fprintf(cgiOut, "</html>\n");
}
