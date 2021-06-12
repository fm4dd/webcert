CC=gcc
CFLAGS= -I../cgic -O3 -Wall -g
LIBS= -L../cgic -lcgic -lm -lssl -lcrypto
AR=ar

HTMDIR=/srv/www/webcert
CGIDIR=/srv/www/webcert/cgi-bin
EXPORTDIR=/srv/www/webcert/export

ALLCGI=buildrequest.cgi genrequest.cgi certsign.cgi certrequest.cgi certverify.cgi showhtml.cgi getcert.cgi certstore.cgi certsearch.cgi certexport.cgi certvalidate.cgi p12convert.cgi keycompare.cgi certrenew.cgi certrevoke.cgi crlstore.cgi

ALLJS=webcert.js

all: ${ALLCGI}

install: 
	strip ${ALLCGI}
	cp ${ALLJS} ${HTMDIR}
	@echo "Checking for cgi dir ${CGIDIR}:"; \
	if test -d ${CGIDIR}; then \
		echo "...OK. ${CGIDIR} exists."; \
		cp ${ALLCGI} ${CGIDIR}; \
                chmod 755 ${CGIDIR}/*; \
		echo "${ALLCGI} installed in ${CGIDIR}."; \
	else \
		echo "Please do: mkdir ${CGIDIR}."; \
		echo "It should be writeable for the installer."; \
	fi \

	@echo "Checking for new export dir needed by certexport.cgi:"; \
	if test -d ${EXPORTDIR}; then echo "...OK. ${EXPORTDIR} exists."; \
	else echo "Please do: mkdir ${EXPORTDIR}."; \
	echo "It should be writeable by the webserver."; fi

clean:
	rm -f *.o *.cgi

buildrequest.cgi: buildrequest.o pagehead.o pagefoot.o handle_error.o serial.o revocation.o webcert.o
	$(CC) serial.o revocation.o webcert.o buildrequest.o pagehead.o pagefoot.o handle_error.o -o buildrequest.cgi ${LIBS}

genrequest.cgi: serial.o revocation.o webcert.o genrequest.o pagehead.o pagefoot.o handle_error.o
	$(CC) serial.o revocation.o webcert.o handle_error.o genrequest.o pagehead.o pagefoot.o -o genrequest.cgi ${LIBS}

certsign.cgi: webcert.o pagehead.o pagefoot.o handle_error.o serial.o certsign.o
	$(CC) serial.o revocation.o webcert.o pagehead.o pagefoot.o handle_error.o certsign.o -o certsign.cgi ${LIBS}

certrequest.cgi: certrequest.o
	$(CC) certrequest.o pagehead.o pagefoot.o -o certrequest.cgi ${LIBS}

certverify.cgi: webcert.o certverify.o
	$(CC) serial.o revocation.o webcert.o certverify.o pagehead.o pagefoot.o handle_error.o -o certverify.cgi ${LIBS}

showhtml.cgi: showhtml.o
	$(CC) showhtml.o pagehead.o pagefoot.o handle_error.o -o showhtml.cgi ${LIBS}

getcert.cgi: webcert.o revocation.o getcert.o
	$(CC) serial.o webcert.o revocation.o getcert.o pagehead.o pagefoot.o handle_error.o -o getcert.cgi ${LIBS}

certstore.cgi: revocation.o certstore.o
	$(CC) serial.o revocation.o certstore.o pagehead.o pagefoot.o handle_error.o -o certstore.cgi ${LIBS}

crlstore.cgi: webcert.o crlstore.o
	$(CC) serial.o revocation.o webcert.o crlstore.o pagehead.o pagefoot.o handle_error.o -o crlstore.cgi ${LIBS}

certsearch.cgi: revocation.o certsearch.o
	$(CC) serial.o revocation.o certsearch.o pagehead.o pagefoot.o handle_error.o -o certsearch.cgi ${LIBS}

certexport.cgi: webcert.o certexport.o
	$(CC) serial.o revocation.o webcert.o certexport.o pagehead.o pagefoot.o handle_error.o -o certexport.cgi ${LIBS}

certvalidate.cgi: webcert.o certvalidate.o
	$(CC) serial.o revocation.o webcert.o certvalidate.o pagehead.o pagefoot.o handle_error.o -o certvalidate.cgi ${LIBS}

p12convert.cgi: webcert.o p12convert.o
	$(CC) serial.o revocation.o webcert.o p12convert.o pagehead.o pagefoot.o handle_error.o -o p12convert.cgi ${LIBS}

keycompare.cgi: webcert.o keycompare.o
	$(CC) serial.o revocation.o webcert.o keycompare.o pagehead.o pagefoot.o handle_error.o -o keycompare.cgi ${LIBS}

certrenew.cgi: webcert.o certrenew.o
	$(CC) serial.o revocation.o webcert.o certrenew.o pagehead.o pagefoot.o handle_error.o -o certrenew.cgi ${LIBS}

certrevoke.cgi: webcert.o serial.o revocation.o certrevoke.o
	$(CC) serial.o revocation.o webcert.o certrevoke.o pagehead.o pagefoot.o handle_error.o -o certrevoke.cgi ${LIBS}
