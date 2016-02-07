# Toplevel Makefile

# WWWUSER and WWWGROUP are the uid/gid names
# the webserver is running under. Typically
# its wwwrun and www. The export directory
# needs to be owned by the webserver in order
# to be able to write the export files to it.
WWWUSER=wwwrun
WWWGROUP=www

INSTALL = /usr/bin/install -c
INSTALLDATA = /usr/bin/install -c -m 644

CADIR=/srv/app/webCA
BASEDIR=/srv/www/std-root/fm4dd.com/sw
HTMDIR=${BASEDIR}/webcert
STLDIR=${BASEDIR}/webcert/style
IMGDIR=${BASEDIR}/webcert/images
CGIDIR=${BASEDIR}/webcert/cgi-bin
EXPORTDIR=${BASEDIR}/webcert/export

ALLHTM=html/*.htm
ALLSTL=style/style.css
ALLIMG=images/*.gif
ALLCGI=src/buildrequest.cgi src/certsign.cgi src/certrequest.cgi src/certverify.cgi src/showhtml.cgi src/getcert.cgi src/certstore.cgi src/certsearch.cgi src/certexport.cgi src/p12convert.cgi src/certrenew.cgi
ALLSCR=scripts/*.sh

all: 
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
	cd src && ${MAKE} clean
