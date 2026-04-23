#!/bin/bash
##########################################################
# verisign-bundle-update.sh 20120618 Frank4DD
# weekly download of the latest verisign ca certificates
##########################################################
# set debug: 0=off 1=normal  2=verbose
DEBUG=1

##########################################################
# binaries location
##########################################################
CURL="/usr/bin/curl"
UNZIP="/usr/bin/unzip"
LOGGER="/usr/bin/logger"
DATE="/bin/date"
BINARIES="$DATE $CURL $UNZIP $LOGGER"

##########################################################
# directories
##########################################################
TEMP_DIR="/tmp"
PROG_DIR="/srv/app/webCA/ca-bundles"

##########################################################
# TIMESTAMP contains current time, i.e. "20061211_1014"
##########################################################
TIMESTAMP=`$DATE +"%Y%m%d_%H%M"`

##########################################################
# HISTORY contains the number of how many files we keep
##########################################################
HISTORY="4"

##########################################################
# Download URL
##########################################################
BUNDLE_URL="https://www.symantec.com/content/en/us/enterprise/verisign/roots/roots.zip"
BUNDLE_ZIP="verisign-bundle-$TIMESTAMP.zip"
BUNDLE_PEM="verisign-bundle-$TIMESTAMP.pem"

##########################################################
# Add Intermediate CA certs
##########################################################
INTERMEDIATES="/srv/app/webCA/ca-downloads/verisign-intermediate-20120914.pem"

##########################################################
############# function definitions #######################
##########################################################

##########################################################
# function check_binaries
##########################################################
CHECK_BINARIES() {
for BIN in $BINARIES; do
  if [ $DEBUG == "2" ]; then echo "CHECK_BINARIES(): $BIN"; fi
  [ ! -x $BIN ] && { echo "$BIN not found, exiting."; exit -1; }
done
}

##########################################################
# function GET_BUNDLE gets the latest version
##########################################################
GET_BUNDLE() {

  # delete potential leftovers
  for FILE in $TEMP_DIR/verisign-bundle-*.zip; do
    if [ -f "$FILE" ]; then
      EXECUTE="/bin/rm $FILE"
      if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
      `$EXECUTE`
    fi
  done

  EXECUTE="$CURL -L -s -f $BUNDLE_URL -o $TEMP_DIR/$BUNDLE_ZIP"
  if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
  `$EXECUTE`
  RC=$?
  if [ $RC -ne 0 ] && [ $RC -ne 2 ]; then
    echo "verisign-bundle-update.sh: curl failed with return code $RC."
  fi

  if [ -s $TEMP_DIR/$BUNDLE_ZIP ]; then 
    FILESIZE=`du -h $TEMP_DIR/$BUNDLE_ZIP | cut -f 1,1`
    $LOGGER -p user.info $ADD_STDERR "verisign-bundle-update.sh: Downloaded $PROG_DIR/$BUNDLE_ZIP [$FILESIZE]."
  fi 
}

##########################################################
# function BUILD_PEM builds the PEM bundle from the ZIP
##########################################################
BUILD_PEM() {

  # delete potential leftovers
  for FILE in $TEMP_DIR/verisign-*; do
    if [ -d "$FILE" ]; then
      EXECUTE="/bin/rm -rf $FILE"
      if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
      `$EXECUTE`
    fi
  done

  EXECUTE="/bin/mkdir $TEMP_DIR/verisign-$TIMESTAMP"
  if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
  `$EXECUTE`

  $UNZIP -q -a $TEMP_DIR/$BUNDLE_ZIP '*.pem' -d $TEMP_DIR/verisign-$TIMESTAMP
  #if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
  #`$EXECUTE`

  RC=$?
  if [ $RC -ne 0 ]; then
    echo "verisign-bundle-update.sh: Unzip to $TEMP_DIR/verisign-$TIMESTAMP failed with return code $RC."
  else
    DIRSIZE=`du -sh $TEMP_DIR/verisign-$TIMESTAMP | cut -f 1,1`
    $LOGGER -p user.info $ADD_STDERR "verisign-bundle-update.sh: Extracted $DIRSIZE to $TEMP_DIR/verisign-$TIMESTAMP."
  fi

OIFS="$IFS"
IFS=$'\n' 
  for FILE in `find $TEMP_DIR/verisign-$TIMESTAMP -type f -name '*.pem'`; do
    # workaround for Verisign giving Macbooks to their staff
    # Mac OSX includes Metadata in zips by default, annoying all non-Mac users
    # old line: cat $FILE >> $PROG_DIR/$BUNDLE_PEM
    # new: use IF/Then to filter the crappy files under __MACOSX
    IGNORE="__MACOSX"
    if [[ $FILE != *"$IGNORE"* ]]; then 
      if [ $DEBUG == "2" ]; then echo $FILE; fi
      cat $FILE >> $PROG_DIR/$BUNDLE_PEM;
      echo >> $PROG_DIR/$BUNDLE_PEM
    fi
  done
IFS="$OIFS"

  EXECUTE="/bin/cat $INTERMEDIATES >> $PROG_DIR/$BUNDLE_PEM"
  if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
  /bin/cat $INTERMEDIATES >> $PROG_DIR/$BUNDLE_PEM

  RC=$?
  if [ $RC -ne 0 ]; then
    echo "verisign-bundle-update.sh: $EXECUTE failed with return code $RC."
  else
    $LOGGER -p user.info $ADD_STDERR "verisign-bundle-update.sh: Added $INTERMEDIATES to $PROG_DIR/$BUNDLE_PEM."
  fi

  if [ -s $PROG_DIR/$BUNDLE_PEM ]; then
    FILESIZE=`du -h $PROG_DIR/$BUNDLE_PEM | cut -f 1,1`
    $LOGGER -p user.info $ADD_STDERR "verisign-bundle-update.sh: Created $PROG_DIR/$BUNDLE_PEM [$FILESIZE]."
  else
    $LOGGER -p user.info $ADD_STDERR "verisign-bundle-update.sh: Error creating $PROG_DIR/$BUNDLE_PEM."
  fi

  if [ -s $TEMP_DIR/$BUNDLE_ZIP ]; then
    EXECUTE="/bin/rm $TEMP_DIR/$BUNDLE_ZIP"
    if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
    `$EXECUTE`
  fi

  if [ -s $TEMP_DIR/verisign-$TIMESTAMP ]; then
    EXECUTE="/bin/rm -rf $TEMP_DIR/verisign-$TIMESTAMP"
    if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
    `$EXECUTE`
  fi
}

##########################################################
# function EXPIRE_BUNDLE
##########################################################
 EXPIRE_BUNDLE() {
  OLDLIST=`ls -r1 $PROG_DIR/verisign-bundle-* |  tail -n +$(($HISTORY+1))`

  for FILE in $OLDLIST; do
    FILESIZE=`du -h $FILE | cut -f 1,1`
    EXECUTE="/bin/rm $FILE"

    if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
    `$EXECUTE`
    $LOGGER -p user.info $ADD_STDERR "verisign-bundle-update.sh: Expiration $FILE [$FILESIZE]."
  done
}

##########################################################
################# MAIN ###################################
##########################################################
if [ $DEBUG == "2" ]; then ADD_STDERR="-s"; fi

CHECK_BINARIES

  if [ $DEBUG == "2" ]; then 
    echo "verisign-bundle-update.sh: Starting `date`."
  fi

GET_BUNDLE

BUILD_PEM

EXPIRE_BUNDLE

  if [ $DEBUG == "2" ]; then 
    echo "verisign-bundle-update.sh: Finished job `date`."
  fi
################# END of MAIN #############################
