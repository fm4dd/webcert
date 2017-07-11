#!/bin/sh
##########################################################
# setup.sh 20170708 Frank4DD
#
# This script creates the required application structure,
# e.g. creates directories and CA files for WebCert.
#
# Run as root.
##########################################################
WEBCA_HOME=/srv/app/webCA
WEBCA_BASE=/var/www/html/webcert


echo "Check for $WEBCA_HOME folder."
if [ -d $WEBCA_HOME ]; then
   ls -ld $WEBCA_HOME
   echo "$WEBCA_HOME folder exists."
else
   echo "Creating $WEBCA_HOME folder..."
   mkdir $WEBCA_HOME
   chmod 750 $WEBCA_HOME
   chgrp www-data $WEBCA_HOME
   ls -ld $WEBCA_HOME
fi
echo "Done."
echo

echo "Check for $WEBCA_HOME/private folder."
if [ -d $WEBCA_HOME/private ]; then
   ls -ld $WEBCA_HOME/private
   echo "$WEBCA_HOME/private folder exists."
else
   echo "Creating $WEBCA_HOME/private folder..."
   mkdir $WEBCA_HOME/private
   chmod 750 $WEBCA_HOME/private
   chgrp www-data $WEBCA_HOME/private
   ls -ld $WEBCA_HOME/private
fi
echo "Done."
echo

echo "Check for $WEBCA_HOME/private/cakey.pem private key."
if [ -f $WEBCA_HOME/private/cakey.pem ]; then
   ls -l $WEBCA_HOME/private/cakey.pem
   echo "$WEBCA_HOME/private/cakey.pem private key exists."
else
   echo "Creating $WEBCA_HOME/private/cakey.pem private key..."
   openssl genrsa -aes256 -out $WEBCA_HOME/private/cakey.pem 4096
   chmod 640 $WEBCA_HOME/private/cakey.pem
   chgrp www-data $WEBCA_HOME/private/cakey.pem
   ls -l $WEBCA_HOME/private/cakey.pem
fi
echo "Done."
echo

echo "Check for $WEBCA_HOME/cacert.pem CA certificate."
if [ -f $WEBCA_HOME/cacert.pem ]; then
   ls -l $WEBCA_HOME/cacert.pem
   echo "$WEBCA_HOME/cacert.pem CA certificate exists."
else
   echo "Creating $WEBCA_HOME/cacert.pem CA certificate..."
   openssl req -new -x509 -days 1826 -key $WEBCA_HOME/private/cakey.pem -out $WEBCA_HOME/cacert.pem
   chmod 640 $WEBCA_HOME/cacert.pem
   chgrp www-data $WEBCA_HOME/cacert.pem
   ls -l $WEBCA_HOME/cacert.pem
fi
echo "Done."
echo

echo "Check for $WEBCA_HOME/serial file."
if [ -f $WEBCA_HOME/serial ]; then
   ls -l $WEBCA_HOME/serial
   echo "$WEBCA_HOME/serial file exists, content:"
   cat $WEBCA_HOME/serial
   echo OK
else
   echo "Creating $WEBCA_HOME/serial..."
   echo "00" >  $WEBCA_HOME/serial
   chmod 660 $WEBCA_HOME/serial
   chgrp www-data $WEBCA_HOME/serial
   ls -l $WEBCA_HOME/serial
   cat $WEBCA_HOME/serial
fi
echo "Done."
echo

echo "Check for $WEBCA_HOME/certs folder."
if [ -d $WEBCA_HOME/certs ]; then
   ls -ld $WEBCA_HOME/certs
   echo "$WEBCA_HOME/certs folder exists"
   echo OK
else
   echo "Creating $WEBCA_HOME/certs..."
   mkdir $WEBCA_HOME/certs
   chmod 770 $WEBCA_HOME/certs
   chgrp www-data $WEBCA_HOME/certs
   ls -ld $WEBCA_HOME/certs
fi
echo "Done."
echo

echo "Check for $WEBCA_BASE folder."
if [ -d $WEBCA_BASE ]; then
   ls -ld $WEBCA_BASE
   echo "$WEBCA_BASE folder exists."
else
   echo "Creating $WEBCA_BASE folder..."
   mkdir $WEBCA_BASE
   chmod 750 $WEBCA_BASE
   chgrp www-data $WEBCA_BASE
   ls -ld $WEBCA_BASE
fi
echo "Done."
echo

echo "Check for $WEBCA_BASE/style folder."
if [ -d $WEBCA_BASE/style ]; then
   ls -ld $WEBCA_BASE/style
   echo "$WEBCA_BASE/style folder exists."
else
   echo "Creating $WEBCA_BASE/style folder..."
   mkdir $WEBCA_BASE/style
   chmod 750 $WEBCA_BASE/style
   chgrp www-data $WEBCA_BASE/style
   ls -ld $WEBCA_BASE/style
fi
echo "Done."
echo

echo "Check for $WEBCA_BASE/images folder."
if [ -d $WEBCA_BASE/images ]; then
   ls -ld $WEBCA_BASE/images
   echo "$WEBCA_BASE/images folder exists."
else
   echo "Creating $WEBCA_BASE/images folder..."
   mkdir $WEBCA_BASE/images
   chmod 750 $WEBCA_BASE/images
   chgrp www-data $WEBCA_BASE/images
   ls -ld $WEBCA_BASE/images
fi
echo "Done."
echo

echo "Check for $WEBCA_BASE/cgi-bin folder."
if [ -d $WEBCA_BASE/cgi-bin ]; then
   ls -ld $WEBCA_BASE/cgi-bin
   echo "$WEBCA_BASE/cgi-bin folder exists."
else
   echo "Creating $WEBCA_BASE/cgi-bin folder..."
   mkdir $WEBCA_BASE/cgi-bin
   chmod 750 $WEBCA_BASE/cgi-bin
   chgrp www-data $WEBCA_BASE/cgi-bin
   ls -ld $WEBCA_BASE/cgi-bin
fi
echo "Done."
echo

echo "Check for $WEBCA_BASE/export folder."
if [ -d $WEBCA_BASE/export ]; then
   ls -ld $WEBCA_BASE/export
   echo "$WEBCA_BASE/export folder exists"
   echo OK
else
   echo "Creating $WEBCA_BASE/export..."
   mkdir $WEBCA_BASE/export
   chmod 770 $WEBCA_BASE/export
   chgrp www-data $WEBCA_BASE/export
   ls -ld $WEBCA_BASE/export
fi
echo "Done."
echo "End of setup.sh"
