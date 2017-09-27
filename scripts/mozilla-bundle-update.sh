#!/bin/bash
##########################################################
# mozilla-bundle-update.sh 20120618 Frank4DD
# download the weekly firefox ca certificate list extract
##########################################################
# set debug: 0=off 1=normal  2=verbose
DEBUG=0

##########################################################
# binaries location
##########################################################
CURL="/usr/bin/curl"
LOGGER="/usr/bin/logger"
DATE="/bin/date"
BINARIES="$DATE $CURL $LOGGER"

##########################################################
# directories
##########################################################
PROG_DIR="/srv/app/webCA/ca-bundles"

##########################################################
# TIMESTAMP contains current time, i.e. "20061211-1014"
##########################################################
TIMESTAMP=`$DATE +"%Y%m%d_%H%M"`

##########################################################
# HISTORY contains the number of how many files we keep
##########################################################
HISTORY="4"

##########################################################
# Download URL
##########################################################
BUNDLE_URL="https://curl.haxx.se/ca/cacert.pem"
ARCH_NAME="mozilla-bundle-$TIMESTAMP.pem"

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
  EXECUTE="$CURL -s -f $BUNDLE_URL -o $PROG_DIR/$ARCH_NAME"

  if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
  `$EXECUTE`
  RC=$?
  if [ $RC -ne 0 ] && [ $RC -ne 2 ]; then
    echo "mozilla-bundle-update.sh: curl failed with return code $RC."
  else
    FILESIZE=`du -h $PROG_DIR/$ARCH_NAME | cut -f 1,1`
  fi

  if [ -s $PROG_DIR/$ARCH_NAME ]; then 
    chmod 444 $PROG_DIR/$ARCH_NAME
    if [ $DEBUG == "2" ]; then 
      echo "mozilla-bundle-update.sh: Enabled apache read access for $PROG_DIR/$ARCH_NAME."
    fi
    $LOGGER -p user.info $ADD_STDERR "mozilla-bundle-update.sh: Downloaded $PROG_DIR/$ARCH_NAME [$FILESIZE]."
  fi 
}

##########################################################
# function EXPIRE_BUNDLE
##########################################################
 EXPIRE_BUNDLE() {
  OLDLIST=`ls -r1 $PROG_DIR/mozilla-bundle-* |  tail -n +$(($HISTORY+1))`
 
  for FILE in $OLDLIST; do
    FILESIZE=`du -h $FILE | cut -f 1,1`
    EXECUTE="/bin/rm $FILE"
 
    if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
    `$EXECUTE`
    $LOGGER -p user.info $ADD_STDERR "mozilla-bundle-update.sh: Expiration $FILE [$FILESIZE]."
  done
}

##########################################################
################# MAIN ###################################
##########################################################
if [ $DEBUG == "2" ]; then ADD_STDERR="-s"; fi

CHECK_BINARIES

  if [ $DEBUG == "2" ]; then 
    echo "mozilla-bundle-update.sh: Starting `date`."
  fi

GET_BUNDLE

EXPIRE_BUNDLE

  if [ $DEBUG == "2" ]; then 
    echo "mozilla-bundle-update.sh: Finished job `date`."
  fi
################# END of MAIN #############################
