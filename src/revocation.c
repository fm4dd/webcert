/* ---------------------------------------------------------- *
 * file:	revocation.c                                  *
 * purpose:	provide revocation related functions          *
 *                                                            *
 * functions here were taken from OpenSSL ca.c and apps.c     *
 * -----------------------------------------------------------*/
#include <string.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/ocsp.h>
#include <openssl/conf.h>
#include "webcert.h"

#define BSIZE           256
#define B_FORMAT_TEXT   0x8000
#define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */

#define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define NUM_REASONS OSSL_NELEM(crl_reasons)    /* crl_reasons see webcert.h */

/* OpenSSL-defined CRL revocation reason strings */
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

/* ---------------------------------------------------------- *
 * OPENSSL_strlcpy(): 1:1 copy from OpenSSL crypto/o_str.c    *
 * New function not linkable against older OpenSSL versions.  *
 * ---------------------------------------------------------- */
size_t OPENSSL_strlcpy(char *dst, const char *src, size_t size) {
    size_t l = 0;
    for (; size > 1 && *src; size--) {
        *dst++ = *src++;
        l++;
    }
    if (size) *dst = '\0';
    return l + strlen(src);
}

/* ---------------------------------------------------------- *
 * OPENSSL_strlcat(): 1:1 copy from OpenSSL crypto/o_str.c    *
 * New function not linkable against older OpenSSL versions.  *
 * ---------------------------------------------------------- */
size_t OPENSSL_strlcat(char *dst, const char *src, size_t size) {
    size_t l = 0;
    for (; size > 0 && *dst; size--, dst++) l++;
    return l + OPENSSL_strlcpy(dst, src, size);
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
 * save_index(): writes a index database to a local file.     *
 * returns 1 for success, or 0 for errors.                    *
 * ---------------------------------------------------------- */
int save_index(const char *dbfile, CA_DB *db) {
  char buf[2][BSIZE];
  BIO *out;
  int j;

  j = strlen(dbfile);
  if (j + 6 >= BSIZE)
    int_error("file name too long");

  j = BIO_snprintf(buf[1], sizeof buf[1], "%s.attr", dbfile);
  j = BIO_snprintf(buf[0], sizeof buf[0], "%s", dbfile);

  out = BIO_new_file(buf[0], "w");
  if (out == NULL) {
     snprintf(error_str, sizeof(error_str), "Unable to write %s.", dbfile);
     int_error(error_str);
  }

  j = TXT_DB_write(out, db->db);
  BIO_free(out);
  if (j <= 0) int_error("TXT_DB_write failed to write data");

  out = BIO_new_file(buf[1], "w");
  if (out == NULL) {
     snprintf(error_str, sizeof(error_str), "Unable to write %s.", dbfile);
     int_error(error_str);
  }

  BIO_printf(out, "unique_subject = %s\n", db->attributes.unique_subject ? "yes" : "no");
  BIO_free(out);
  return 1;
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
/* ------------------------------------------------------------- *
 * Function cgi_gencrl() generates a new CRL file from DB file   *
 * index.txt. This function is based on opensssl's apps/ca.c.    *
 * ------------------------------------------------------------- */
int cgi_gencrl(char *crlfile) {
    
  /* ------------------------------------------------------------- *
   * Load the CRL serial number from file (defined in webcert.h)   *
   * ------------------------------------------------------------- */
  BIGNUM *crlnumber;
  if ((crlnumber = load_serial(CRLSEQNUM, 1, NULL)) == NULL)
    int_error("Error loading CRL serial number from file");

  /* ----------------------------------------------------------- *
   * increment the serial number                                 *
   * ------------------------------------------------------------*/
   if (! (BN_add_word(crlnumber,1)))
      int_error("Error incrementing CRL serial number");

  // *** debug: output the serial # to screen
  //unsigned char crlsn_str[BN_num_bytes(crlnumber)];
  //BN_bn2bin(crlnumber, crlsn_str);
  //snprintf(error_str, sizeof(error_str), "Check: %d", (int)crlsn_str[0]);
  //int_error(error_str);

  /* ----------------------------------------------------------- *
   * save the serial number back to SERIALFILE                   *
   * ------------------------------------------------------------*/
   ASN1_INTEGER *aserial = NULL;
   if ( save_serial(CRLSEQNUM, 0, crlnumber, &aserial) == 0 )
      int_error("Error writing serial number to file");

  /* ------------------------------------------------------------- *
   * Create a new CRL object, and set issuer from CA cert          *
   * ------------------------------------------------------------- */
  X509_CRL *crl = NULL;
  if ((crl = X509_CRL_new()) == NULL)
    int_error("Error creating a new CRL object");

  FILE  *certfile = NULL;
  if (! (certfile = fopen(CACERT, "r")))
    int_error("Error can't open CA certificate file");

  X509 *cacert = NULL;
  if (! (cacert = PEM_read_X509(certfile,NULL,NULL,NULL)))
    int_error("Error loading CA cert into memory");
  fclose(certfile);

  if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(cacert)))
    int_error("Error setting issuer name to CRL object");

  /* ------------------------------------------------------------- *
   * Set the CRL current date and expiration date                  *
   * TODO: hardcoded values                                        *
   * ------------------------------------------------------------- */
  int crldays = 30;
  int crlhours = 0;
   
  ASN1_TIME *tmptm = NULL;
  tmptm = ASN1_TIME_new();
  if (tmptm == NULL) 
    int_error("Error cannot get current ASN1_TIME");

  X509_gmtime_adj(tmptm, 0);
  X509_CRL_set_lastUpdate(crl, tmptm);
  if (!X509_time_adj_ex(tmptm, crldays, crlhours * 60 * 60, NULL))
      int_error("Error setting CRL nextUpdate");

  X509_CRL_set_nextUpdate(crl, tmptm);
  ASN1_TIME_free(tmptm);

  /* ------------------------------------------------------------- *
   * Set CRL version 2, which supports extensions, e.g. CRL serial *
   * ------------------------------------------------------------- */
  if (!X509_CRL_set_version(crl, 1))
    int_error("Error cannot set CRL version 2");

  /* ------------------------------------------------------------- *
   * Read all revoked certitifcates from the internal index.txt db *
   * ------------------------------------------------------------- */
  CA_DB *db = NULL;
  DB_ATTR db_attr;

  if((db = load_index(INDEXFILE, &db_attr)) == NULL)
    int_error("Error cannot load CRL certificate database file");

  /* ------------------------------------------------------------- *
   * Read all revoked certitifcates from the internal index.txt db *
   * ------------------------------------------------------------- */
  int i, j;
  char *const *pp;
  X509_REVOKED *r = NULL;
  BIGNUM *certserial = NULL;
  ASN1_INTEGER *tmpser = NULL;

  for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
    pp = sk_OPENSSL_PSTRING_value(db->db->data, i);

    // *** debug: cycle DB_NUMBER should show each field in index.db
    //for (j = 0; j < DB_NUMBER; j++) { 
    //  snprintf(error_str, sizeof(error_str), " %d = \"%s\"", j, pp[j]);
    //} 
    //int_error(error_str);

    /* ------------------------------------------------------------- *
     * Check if the cert entry in index.db is in state 'R' = revoked *
     * ------------------------------------------------------------- */
    // ***  "Debug %d=\"%c\"", i, pp[DB_type][0] -> Debug 0="R"
    if (pp[DB_type][0] == DB_TYPE_REV) {
      if ((r = X509_REVOKED_new()) == NULL)
        int_error("Error creating X509_REVOKED object");

      /* ------------------------------------------------------------- *
       * Create the X509_Revoked object, using the index.db timestamp  *
       * ------------------------------------------------------------- */
      // *** "Debug i=%d str=%s, j=%d", i, pp[DB_rev_date], j -> Debug i=0 str=170821044339Z, j=1
      j = make_revoked(r, pp[DB_rev_date]);
      if (!j) break;

      /* ------------------------------------------------------------- *
       * Add the certificate serial to the X509_Revoked object         *
       * ------------------------------------------------------------- */
      // *** "Debug i=%d str=%s, j=%d", i, pp[DB_serial], j -> Debug i=0 str=1A, j=1
      if (!BN_hex2bn(&certserial, pp[DB_serial])) break;
      tmpser = BN_to_ASN1_INTEGER(certserial, NULL);

      if (!tmpser) break;
      X509_REVOKED_set_serialNumber(r, tmpser);

      /* ------------------------------------------------------------- *
       * Add the revoked cert entry to the crl object                  *
       * ------------------------------------------------------------- */
      X509_CRL_add0_revoked(crl, r);
    }
  }

  BN_free(certserial);
  TXT_DB_free(db->db);
  OPENSSL_free(db);

  /* ------------------------------------------------------------- *
   * sort the data so it will be written in serial number order    *
   * ------------------------------------------------------------- */
  X509_CRL_sort(crl);

  /* ------------------------------------------------------------- *
   * Add CRL extensions                                            *
   * ------------------------------------------------------------- */
  X509 *x509 = NULL;
  X509V3_CTX crlctx;
  X509V3_set_ctx(&crlctx, x509, NULL, NULL, crl, 0);

  tmpser = BN_to_ASN1_INTEGER(crlnumber, NULL);

  if (tmpser)
    X509_CRL_add1_ext_i2d(crl, NID_crl_number, tmpser, 0, 0);

  ASN1_INTEGER_free(tmpser);

  /* ------------------------------------------------------------- *
   * Add CRL serial number extension                               *
   * ------------------------------------------------------------- */
  if (!BN_add_word(crlnumber, 1))
    int_error("Error adding CRL serial extension value");

  BN_free(crlnumber);

  /* ------------------------------------------------------------- *
   * Import CA private key for signing                             *
   * --------------------------------------------------------------*/
  FILE *key_fp;
  EVP_PKEY *ca_privkey;
  ca_privkey = EVP_PKEY_new();

  if (!(key_fp = fopen(CAKEY, "r")))
    int_error("Error reading CA private key file");

  if (!(ca_privkey = PEM_read_PrivateKey(key_fp, NULL, NULL, PASS)))
    int_error("Error importing key content from file");

  fclose(key_fp);

  /* ------------------------------------------------------------- *
   * Sign the CRL with the CA's private key, hardcoded with SHA256 *
   * ------------------------------------------------------------- */
  const EVP_MD *digest = EVP_sha256();
  if (!X509_CRL_sign(crl, ca_privkey, digest))
    int_error("Error signing CRL with CA private key");

  EVP_PKEY_free(ca_privkey);

  /* ------------------------------------------------------------- *
   * Write the CRL data into a PEM file for download               *
   * ------------------------------------------------------------- */
  FILE *fp;
  if (! (fp=fopen(CRLFILE, "w")))
    int_error("Error opening CRL file for writing");

  BIO *savbio = BIO_new(BIO_s_file());
  BIO_set_fp(savbio, fp, BIO_NOCLOSE);

  if (! PEM_write_bio_X509_CRL(savbio, crl))
    int_error("Error writing PEM data into CRL file");

  BIO_free(savbio);
  fclose(fp);
  X509_free(x509);
  X509_CRL_free(crl);
  return 0;
} // end of function cgi_gencrl()

/* ---------------------------------------------------------- *
 * make_revocation_str() converts revocation info into an DB  *
 * string. Format: revtime[,reason,extra]. Where 'revtime' is *
 * the revocation time (current time). 'reason' is optional   *
 * CRL reason,'extra' is any* additional argument.            *
 * ---------------------------------------------------------- */
static char *make_revocation_str(REVINFO_TYPE rev_type, const char *rev_arg) {
  char *str;
  const char *reason = NULL, *other = NULL;
  ASN1_OBJECT *otmp;
  ASN1_UTCTIME *revtm = NULL;
  int i;

  switch (rev_type) {
    case REV_NONE:
    case REV_VALID:
      break;

    case REV_CRL_REASON:
      for (i = 0; i < 8; i++) { // crl_reasons has 8 core entries
        if (strcasecmp(rev_arg, crl_reasons[i]) == 0) {
          reason = crl_reasons[i];
          break;
        }
      }
      if (reason == NULL) {
        snprintf(error_str, sizeof(error_str), "Unknown CRL reason %s", rev_arg);
        int_error(error_str);
      }
      break;

    case REV_HOLD:
      /* Argument is an OID */
      otmp = OBJ_txt2obj(rev_arg, 0);
      ASN1_OBJECT_free(otmp);

      if (otmp == NULL) {
        snprintf(error_str, sizeof(error_str), "Invalid object identifier %s", rev_arg);
        int_error(error_str);
      }

      reason = "holdInstruction";
      other = rev_arg;
      break;

    case REV_KEY_COMPROMISE:
    case REV_CA_COMPROMISE:
      /* Argument is the key compromise time  */
      if (!ASN1_GENERALIZEDTIME_set_string(NULL, rev_arg)) {
        snprintf(error_str, sizeof(error_str), "Invalid time format %s, should be YYYYMMDDHHMMSSZ", rev_arg);
        int_error(error_str);
      }
      other = rev_arg;
      if (rev_type == REV_KEY_COMPROMISE) reason = "keyTime";
      else reason = "CAkeyTime";
      break;
    }

    revtm = X509_gmtime_adj(NULL, 0);

    if (!revtm) return NULL;

    i = revtm->length + 1;

    if (reason) i += strlen(reason) + 1;
    if (other) i += strlen(other) + 1;

    str = OPENSSL_malloc(i);  // revocation reason
    OPENSSL_strlcpy(str, (char *)revtm->data, i);

    if (reason) {
        OPENSSL_strlcat(str, ",", i);
        OPENSSL_strlcat(str, reason, i);
    }
    if (other) {
        OPENSSL_strlcat(str, ",", i);
        OPENSSL_strlcat(str, other, i);
    }
    ASN1_UTCTIME_free(revtm);
    return str;
}

/* ---------------------------------------------------------- *
 * do_revoke() takes a cert object, checks existence in the   *
 * CA database index.txt, and creates the certs entry line of *
 * revoked state, timestamp and revocation reason.            *
 * -----------------------------------------------------------*/
int do_revoke(X509 *x509, CA_DB *db, const char *value) {
  char *row[DB_NUMBER], **rrow;

  /* ---------------------------------------------------------- *
   * Zero out the row field array                               *
   * -----------------------------------------------------------*/
  int i;
  for (i=0; i<DB_NUMBER; i++) row[i] = NULL;

  /* ---------------------------------------------------------- *
   * Set status field as type "R" revoked for DB field (0)      *
   * -----------------------------------------------------------*/
  row[DB_type] = OPENSSL_strdup("R");

  /* ---------------------------------------------------------- *
   * Set the cert expiration in date field (1)                  *
   * -----------------------------------------------------------*/
  const ASN1_TIME *tm = NULL;
  tm = X509_get_notAfter(x509);
  row[DB_exp_date] = OPENSSL_malloc(tm->length + 1);
  memcpy(row[DB_exp_date], tm->data, tm->length);
  row[DB_exp_date][tm->length] = '\0';

  /* ---------------------------------------------------------- *
   * Set the revocation date and reason, add to DB field (2)    *
   * -----------------------------------------------------------*/
  char *rev_str = NULL;
  rev_str = make_revocation_str(REV_CRL_REASON, value);
  if (!rev_str)
      int_error("Error in revocation arguments\n");
  row[DB_rev_date] = rev_str;

  /* ---------------------------------------------------------- *
   * Get the certs serial number, add it to DB field (3)        *
   * -----------------------------------------------------------*/
  BIGNUM *bn = NULL;
  bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), NULL);
  if (!bn)
    int_error("Cannot extract serial number from cert into BIGNUM");
 
  if (BN_is_zero(bn)) row[DB_serial] = OPENSSL_strdup("00");
  else row[DB_serial] = BN_bn2hex(bn);
  BN_free(bn);

  /* ---------------------------------------------------------- *
   * OpenSSL hardcodes the cert filepath field (4) as "unknown" *
   * -----------------------------------------------------------*/
  row[DB_file] = OPENSSL_strdup("unknown");

  /* ---------------------------------------------------------- *
   * Get the certs subject name, and add it to the DB field (5) *
   * -----------------------------------------------------------*/
  row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);

  /* ---------------------------------------------------------- *
   * If any of the above steps fail, create an error and stop   *
   * -----------------------------------------------------------*/
  for (i=0; i<DB_NUMBER; i++) {
    if (row[i] == NULL) int_error("Memory allocation failure");
  }
  
  /* ---------------------------------------------------------- *
   * Try to lookup the cert in the DB by its serial number      *
   * -----------------------------------------------------------*/
  rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
  if (rrow != NULL) {
    int_error("Certificate is already on the list of revoked certs");
  }

  /* ---------------------------------------------------------- *
   * Write the irow string to the CA database object            *
   * -----------------------------------------------------------*/
  if (!TXT_DB_insert(db->db, row)) {
    snprintf(error_str, sizeof(error_str), "Failed to update database, error number %ld.", db->db->error);
    int_error(error_str);
  }

  return (1);
}
