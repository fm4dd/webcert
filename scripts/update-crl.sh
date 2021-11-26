#!/bin/bash
##########################################################
# update-crl.sh - This script checks if there was a update
# to index.txt from a new revocation entry. It then builds
# and publishes a new CRL file. Runs daily from cron.
##########################################################
# set debug: 0=off 1=normal  2=verbose
DEBUG=2

##########################################################
# binaries location
##########################################################
LOGGER="/usr/bin/logger"
DATE="/bin/date"
SHA224="/usr/bin/sha224sum"
OSSL="/usr/bin/openssl"
BINARIES="$DATE $OSSL $SHA224 $LOGGER"

##########################################################
# CRL data file, and CRL data file checksum file
##########################################################
checkfile=/srv/app/webCA/index.txt
sumfile=/srv/app/webCA/index.txt.sha224
crlfile=/srv/www/webcert/webcert.crl
update_crl=0

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
# function check_update identifies if index.txt changed,
# which indicates that a new cert got revoked. Sets
# the flag "update_crl" to 1.
##########################################################
CHECK_UPDATE() {
  if [ -z "$checkfile" -o ! -f "$checkfile" ]; then
    echo "ERROR: cannot find $checkfile"
    exit 1
  elif ! grep -q "$checkfile" $sumfile; then
    echo "ERROR: file $checkfile is not in $sumfile"
    exit 1
  fi

  oldsum=$(cat $sumfile)
  [ $DEBUG == "2" ] && echo "update-crl.sh: old checksum $oldsum"

  newsum=$($SHA224 $checkfile)
  [ $DEBUG == "2" ] && echo "update-crl.sh: new checksum $newsum"

  if grep -q "$newsum" $sumfile; then
    [ $DEBUG == "2" ] && echo "update-crl.sh: $checkfile unchanged, no new revocations"
  else
    update_crl="1"
    [ $DEBUG == "2" ] && echo "update-crl.sh: $checkfile IS MODIFIED, set flag $update_crl"
  fi
}

##########################################################
# function new_crl generates a new CRL file if needed,
# and writes the updated sha224 hash into the checkfile
##########################################################
NEW_CRL() {
  if [ $update_crl == "1" ]; then
    $OSSL ca -cert /srv/app/webCA/cacert.pem -gencrl -crldays 90 \
    -out $crlfile --passin file:/srv/app/webCA/private/passin.src 2>/dev/null

    [ $DEBUG == "2" ] && echo "update-crl.sh: created new crl file $crlfile"
    $LOGGER -p user.info $ADD_STDERR "update-crl.sh: created new crl file $crlfile"

    $SHA224 $checkfile > $sumfile
    [ $DEBUG == "2" ] && echo "update-crl.sh: created new sha224 file $sumfile"
    $LOGGER -p user.info $ADD_STDERR "update-crl.sh: created sha224 file $sumfile"
  fi
}

##########################################################
################# MAIN ###################################
##########################################################
if [ $DEBUG == "2" ]; then ADD_STDERR="-s"; fi

CHECK_BINARIES

if [ $DEBUG == "2" ]; then
  echo "update-crl.sh: Starting `date`."
fi

CHECK_UPDATE

NEW_CRL

if [ $DEBUG == "2" ]; then
  echo "update-crl.sh: Finished job `date`."
fi
################# END of MAIN #############################
