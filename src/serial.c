/* -------------------------------------------------------------------------- *
 * file:	serial.c                                                      *
 * purpose:	provide management functions for serial numbers and file      *
 *                                                                            *
 * functions here were taken from OpenSSL source x509.c, ca.c and apps.c      *
 * ---------------------------------------------------------------------------*/
#include <string.h>
#include <errno.h>
#include <openssl/buffer.h>
#include "webcert.h"
#include <openssl/ocsp.h>
#include <openssl/conf.h>

#define POSTFIX		".srl"
#define SERIAL_RAND_BITS 64
#define BSIZE		256
#define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

#define B_FORMAT_TEXT   0x8000
#define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */

static const char *crl_reasons[] = {
    /* CRL reason strings */
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    /* Additional pseudo reasons */
    "holdInstruction",
    "keyTime",
    "CAkeyTime"
};

#define NUM_REASONS OSSL_NELEM(crl_reasons)


/* ---------------------------------------------------------- *
 * rand_serial(): create random serial number (not yet used)  *
 * returns  1 on success, and 0 for failure                   *
 * ---------------------------------------------------------- */
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai) {
  BIGNUM *btmp;

  if (b) btmp = b;
  else btmp = BN_new();

  if (!btmp) return 0;

  if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0)) goto err;
  if (ai && !BN_to_ASN1_INTEGER(btmp, ai)) goto err;

  return 1;

err:
  if (!b) BN_free(btmp);
  return 0;
}

/* ---------------------------------------------------------- *
 * load_serial(): loads the serial number from a text file    *
 * Returns the serial as a BIGNUM object, or NULL for errors. *
 * ---------------------------------------------------------- */
BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai) {
  BIO *in=NULL;
  BIGNUM *ret=NULL;
  char buf[1024];
  ASN1_INTEGER *ai=NULL;

  ai=ASN1_INTEGER_new();
  if (ai == NULL) goto err;

  if ((in=BIO_new(BIO_s_file())) == NULL) {
    int_error("Error: Can't open new file bio.");
    goto err;
  }

  if (BIO_read_filename(in,serialfile) <= 0) {
    if (!create) {
      int_error(serialfile);
      goto err;
    }
    else {
      if((ret=BN_new()) == NULL)
        int_error("Error: BN_new() Out of memory\n");
    }
  }
  else {
    if (!a2i_ASN1_INTEGER(in,ai,buf,1024)) {
      int_error("Error: unable to load number from serial file.");
      goto err;
    }
    ret=ASN1_INTEGER_to_BN(ai,NULL);
    if (ret == NULL) {
      int_error("Error: converting number from bin to BIGNUM");
      goto err;
    }
  }

  if (ret && retai) {
    *retai = ai;
    ai = NULL;
  }

err:
  if (in != NULL) BIO_free(in);
  if (ai != NULL) ASN1_INTEGER_free(ai);
  return(ret);
}

/* ---------------------------------------------------------- *
 * save_serial(): writes a serial number back to text file    *
 * returns 1 for sucess, and 0 for error.                     *
 * ---------------------------------------------------------- */
int save_serial(char *serialfile, char *suffix, BIGNUM *serial,
                                                ASN1_INTEGER **retai) {
  char buf[1][BSIZE];
  BIO *out = NULL;
  int ret=0;
  ASN1_INTEGER *ai=NULL;
  int j;

  if (suffix == NULL) j = strlen(serialfile);
  else j = strlen(serialfile) + strlen(suffix) + 1;
  if (j >= BSIZE) {
     int_error("Error: File name too long.");
     goto err;
   }

   if (suffix == NULL) BUF_strlcpy(buf[0], serialfile, BSIZE);
   else {
      j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);
   }
   out=BIO_new(BIO_s_file());
   if (out == NULL) {
      int_error("Error: Can't create serial file.");
      goto err;
   }
   if (BIO_write_filename(out,buf[0]) <= 0) {
       int_error("Error: Can't write serial file.");
       goto err;
   }

  if ((ai=BN_to_ASN1_INTEGER(serial,NULL)) == NULL) {
     int_error("Error: converting serial to ASN.1 format");
     goto err;
  }
  i2a_ASN1_INTEGER(out,ai);
  BIO_puts(out,"\n");
  ret=1;
  if (retai) {
     *retai = ai;
     ai = NULL;
  }
err:
  if (out != NULL) BIO_free_all(out);
  if (ai != NULL) ASN1_INTEGER_free(ai);
  return(ret);
}

/* ---------------------------------------------------------- *
 * app_load_config(): loads a config file into a CONF object. *
 * returns pointer to CONF object, or NULL for errors.        *
 * ---------------------------------------------------------- */
CONF *app_load_config(const char *filename) {

  BIO *in;
  if ((in = BIO_new_file(filename, "r")) == NULL) {
    snprintf(error_str, sizeof(error_str),
      "Can't open %s for reading, %s\n",
      filename, strerror(errno));
  }

  CONF *conf = NCONF_new(NULL);

  long errorline = -1;
  int i = NCONF_load_bio(conf, in, &errorline);
  if (i > 0) {
    BIO_free(in);
    return conf;
  }

  if (errorline <= 0) {
    snprintf(error_str, sizeof(error_str),
    "Error: Can't load config file \"%s\"\n", filename);
    int_error(error_str);
  }
  else {
    snprintf(error_str, sizeof(error_str),
    "Error: file \"%s\" problem on line %ld\n", filename, errorline);
    int_error(error_str);
  }
  NCONF_free(conf);
  BIO_free(in);
  return NULL;
}

/* ---------------------------------------------------------- *
 * load_index(): loads a index database into a CA_DB object.  *
 * returns pointer to CA_DB object, or NULL for errors.       *
 * ---------------------------------------------------------- */
CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr) {

  BIO *in;
  if ((in = BIO_new_file(dbfile, "r")) == NULL)
    int_error("Error: cannot open database file for reading");

  TXT_DB *tmpdb = NULL;
  if ((tmpdb = TXT_DB_read(in, DB_NUMBER)) == NULL)
    int_error("Error: cannot create text DB object");

 /* ----------------------------------------------------------- *
  * cat /srv/app/webCA/index.txt.attr --> unique_subject = yes  *
  * ----------------------------------------------------------- */
  char buf[BSIZE];
  BIO_snprintf(buf, sizeof buf, "%s.attr", dbfile);

  CONF *dbattr_conf = NULL;
  dbattr_conf = app_load_config(buf);

  CA_DB *retdb = NULL;
  retdb = OPENSSL_malloc(sizeof(*retdb));
  if (retdb == NULL)
    int_error("Error: cannot allocate memory for new database");
  retdb->db = tmpdb;

  tmpdb = NULL;
  if (db_attr) retdb->attributes = *db_attr;
  else retdb->attributes.unique_subject = 1;

  if (dbattr_conf) {
    char *p = NCONF_get_string(dbattr_conf, NULL, "unique_subject");
    if(strcmp(p, "yes") == 0) {
      retdb->attributes.unique_subject =  1;
    }
  }

  TXT_DB_free(tmpdb);
  BIO_free_all(in);
  return retdb;
}

/* ---------------------------------------------------------- *
 * unpack_revinfo(): extracts the revocation information and  *
 * returns 1 for success, and 0 for errors.                   *
 * ---------------------------------------------------------- */
int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold,
                   ASN1_GENERALIZEDTIME **pinvtm, const char *str) {
  char *tmp;
  char *rtime_str, *reason_str = NULL, *arg_str = NULL, *p;
  int reason_code = -1;
  int ret = 0;
  unsigned int i;
  ASN1_OBJECT *hold = NULL;
  ASN1_GENERALIZEDTIME *comp_time = NULL;

 /* ----------------------------------------------------------- *
  * work on a data copy instead of the original source, examples:
  * R 200817005646Z 170821044339Z	        1A unknown /CN=2ss
  * R 200817005627Z 170822080048Z,keyCompromise	19 unknown /CN=sss
  * ----------------------------------------------------------- */
  tmp = OPENSSL_strdup(str);
  if (!tmp) {
    int_error("Error memory allocation failure");
    goto end;
  }

 /* ----------------------------------------------------------- *
  * if the db line contains a ',', a revoc. reason was given.   *
  * ----------------------------------------------------------- */
  p = strchr(tmp, ',');
  rtime_str = tmp;

  if (p) {
    *p = '\0';
    p++;
    reason_str = p;

    p = strchr(p, ',');
    if (p) {
      *p = '\0';
      arg_str = p + 1;
    }
  }

 /* ----------------------------------------------------------- *
  * Create revoc. time object, set it to the revoc. timestamp   *
  * ----------------------------------------------------------- */
  if (prevtm) {
    *prevtm = ASN1_UTCTIME_new();
    if (*prevtm == NULL) {
      int_error("Error memory allocation failure");
      goto end;
    }

    if (!ASN1_UTCTIME_set_string(*prevtm, rtime_str)) {
      int_error("Error invalid revocation date string");
      goto end;
    }
  }

 /* ----------------------------------------------------------- *
  * Get the revocation reason string, if entered into index.db  *
  * ----------------------------------------------------------- */
  if (reason_str) {
    for (i = 0; i < NUM_REASONS; i++) {
      if (strcasecmp(reason_str, crl_reasons[i]) == 0) {
        reason_code = i;
        break;
      }
    }
    if (reason_code == OCSP_REVOKED_STATUS_NOSTATUS) {
      int_error("Error invalid reason code string");
      goto end;
    }

    if (reason_code == 7) {
      reason_code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
    } 
    else if (reason_code == 8) { /* Hold instruction */
      if (!arg_str) {
        int_error("Error missing hold instruction");
        goto end;
      }
      reason_code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
      hold = OBJ_txt2obj(arg_str, 0);

      if (!hold) {
        int_error("Error invalid object identifier");
        goto end;
      }
      if (phold) *phold = hold;
      else ASN1_OBJECT_free(hold);
    }
    else if ((reason_code == 9) || (reason_code == 10)) {
      if (!arg_str) {
        int_error("Error missing compromised time");
        goto end;
      }
      comp_time = ASN1_GENERALIZEDTIME_new();
      if (comp_time == NULL) {
        int_error("Error memory allocation failure");
        goto end;
      }
      if (!ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str)) {
        int_error("Error invalid compromised time");
        goto end;
      }
      if (reason_code == 9) reason_code = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
      else reason_code = OCSP_REVOKED_STATUS_CACOMPROMISE;
    }
  }

  if (preason) *preason = reason_code;
  if (pinvtm) {
    *pinvtm = comp_time;
    comp_time = NULL;
  }

  ret = 1;

end:
  OPENSSL_free(tmp);
  ASN1_GENERALIZEDTIME_free(comp_time);
  return ret;
}

/* ---------------------------------------------------------- *
 * make_revoked(): create a X509_REVOKED object pointer from  *
 * index.db entries, returns 0 for errors, 1 for success, and *
 * 2 if OK and some extensions were added (i.e. for V2 CRLs). *
 * ---------------------------------------------------------- */
int make_revoked(X509_REVOKED *rev, const char *str) {
  char *tmp = NULL;
  int reason_code = -1;
  int i, ret = 0;
  ASN1_OBJECT *hold = NULL;
  ASN1_GENERALIZEDTIME *comp_time = NULL;
  ASN1_ENUMERATED *rtmp = NULL;
  ASN1_TIME *revDate = NULL;

  i = unpack_revinfo(&revDate, &reason_code, &hold, &comp_time, str);

  if (i == 0) goto end;

  if (rev && !X509_REVOKED_set_revocationDate(rev, revDate))
    goto end;

  if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)) {
    rtmp = ASN1_ENUMERATED_new();
    if (rtmp == NULL || !ASN1_ENUMERATED_set(rtmp, reason_code))
      goto end;
    if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
      goto end;
  }

  if (rev && comp_time) {
    if (!X509_REVOKED_add1_ext_i2d
      (rev, NID_invalidity_date, comp_time, 0, 0))
      goto end;
  }
  if (rev && hold) {
    if (!X509_REVOKED_add1_ext_i2d
      (rev, NID_hold_instruction_code, hold, 0, 0))
      goto end;
  }

  if (reason_code != OCSP_REVOKED_STATUS_NOSTATUS) ret = 2;
  else ret = 1;

end:
  OPENSSL_free(tmp);
  ASN1_OBJECT_free(hold);
  ASN1_GENERALIZEDTIME_free(comp_time);
  ASN1_ENUMERATED_free(rtmp);
  ASN1_TIME_free(revDate);
  return ret;
}
