# Toplevel Makefile

# WWWUSER and WWWGROUP are the uid/gid names
# the webserver is running under. Typically
# its www-data:www-data. The export directory
# needs to be owned by the webserver in order
# to be able to write the export files to it.
WWWUSER=www-data
WWWGROUP=www-data

INSTALL = /usr/bin/install -c
INSTALLDATA = /usr/bin/install -c -m 644

CADIR=/srv/app/webCA
BASEDIR=/srv/www/webcert
HTMDIR=${BASEDIR}
STLDIR=${BASEDIR}/style
IMGDIR=${BASEDIR}/images
CGIDIR=${BASEDIR}/cgi-bin
EXPORTDIR=${BASEDIR}/export

ALLHTM=html/*.htm html/*.shtm
ALLSTL=style/style.css
ALLIMG=images/*.gif images/*.png
ALLCGI=src/buildrequest.cgi src/genrequest.cgi src/certsign.cgi src/certrequest.cgi src/certverify.cgi src/showhtml.cgi src/getcert.cgi src/certstore.cgi src/certsearch.cgi src/certexport.cgi src/certvalidate.cgi src/p12convert.cgi src/keycompare.cgi src/certrenew.cgi src/certrevoke.cgi
ALLSCR=scripts/*.sh

all: 
	cd cgic && ${MAKE}
	cd src && ${MAKE}

install:
	install -v -d ${BASEDIR}
	install -v -d ${HTMDIR}
	install -v -d ${STLDIR}
	install -v -d ${IMGDIR}
	install -v -d ${CGIDIR}
	install -v -d ${EXPORTDIR} -o ${WWWUSER} -g ${WWWGROUP}
	if [ ! -d ${EXPORTDIR} ]; then echo "${EXPORTDIR} does not exist."; exit; fi
	install -v -d ${EXPORTDIR}/tmp -o ${WWWUSER} -g ${WWWGROUP}
	if [ ! -d ${EXPORTDIR}/tmp ]; then echo "${EXPORTDIR}/tmp does not exist."; exit; fi

	@echo -e "\n######## Installing HTML files..."
	install -v  ${ALLHTM} ${HTMDIR}
	@echo -e "\n######## Installing CSS files..."
	install -v ${ALLSTL} ${STLDIR}
	@echo -e "\n######## Installing image files..."
	install -v ${ALLIMG} ${IMGDIR} 
	@echo
	cd ./src && ${MAKE} install

	install -v -d ${CADIR} -o root -g root -m=755
	if [ ! -d ${CADIR} ]; then echo "${CADIR} does not exist."; exit; fi
	install -v -d ${CADIR}/scripts -o root -g root -m=755
	if [ ! -d ${CADIR}/scripts ]; then echo "${CADIR}/scripts does not exist."; exit; fi
	install -v ${ALLSCR} ${CADIR}/scripts

clean:
	cd cgic && ${MAKE} clean
	cd src && ${MAKE} clean
