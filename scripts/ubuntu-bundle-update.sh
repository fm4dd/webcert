#!/bin/bash
##########################################################
# ubuntu-bundle-update.sh 20120829 Frank4DD
# weekly copy of the local certificate list coming with OS
##########################################################
# set debug: 0=off 1=normal  2=verbose
DEBUG=0

##########################################################
# binaries location
##########################################################
CP="/bin/cp"
LOGGER="/usr/bin/logger"
DATE="/bin/date"
BINARIES="$DATE $CP $LOGGER"

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
BNDL_DIR="/etc/ssl/certs"
#BNDL_NAME="/var/lib/ca-certificates/ca-bundle.pem"
ARCH_NAME="ubuntu-bundle-$TIMESTAMP.pem"

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
  touch $PROG_DIR/$ARCH_NAME
  for FILE in $BNDL_DIR/*.pem; do
    if [ $DEBUG == "2" ]; then echo $FILE; fi
    cat $FILE >> $PROG_DIR/$ARCH_NAME
    RC=$?
    if [ $RC -ne 0 ] && [ $RC -ne 2 ]; then
      echo "ubuntu-bundle-update.sh: copy failed with return code $RC."
    fi
  done

  if [ -s $PROG_DIR/$ARCH_NAME ]; then 
    chmod 444 $PROG_DIR/$ARCH_NAME
    if [ $DEBUG == "2" ]; then 
      echo "ubuntu-bundle-update.sh: Enabled apache read access for $PROG_DIR/$ARCH_NAME."
    fi
    FILESIZE=`du -h $PROG_DIR/$ARCH_NAME | cut -f 1,1`
    $LOGGER -p user.info $ADD_STDERR "ubuntu-bundle-update.sh: Copied $PROG_DIR/$ARCH_NAME [$FILESIZE]."
  fi 
}

##########################################################
# function EXPIRE_BUNDLE
##########################################################
 EXPIRE_BUNDLE() {
  OLDLIST=`ls -r1 $PROG_DIR/ubuntu-bundle-* |  tail -n +$(($HISTORY+1))`
 
  for FILE in $OLDLIST; do
    FILESIZE=`du -h $FILE | cut -f 1,1`
    EXECUTE="/bin/rm $FILE"
 
    if [ $DEBUG == "2" ]; then echo $EXECUTE; fi
    `$EXECUTE`
    $LOGGER -p user.info $ADD_STDERR "ubuntu-bundle-update.sh: Expiration $FILE [$FILESIZE]."
  done
}

##########################################################
################# MAIN ###################################
##########################################################
if [ $DEBUG == "2" ]; then ADD_STDERR="-s"; fi

CHECK_BINARIES

  if [ $DEBUG == "2" ]; then 
    echo "ubuntu-bundle-update.sh: Starting `date`."
  fi

GET_BUNDLE

EXPIRE_BUNDLE

  if [ $DEBUG == "2" ]; then 
    echo "ubuntu-bundle-update.sh: Finished job `date`."
  fi
################# END of MAIN #############################
