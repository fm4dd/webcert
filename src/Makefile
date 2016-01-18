CC=gcc
CFLAGS= -O3 -Wall -g
LIBS= -L/home/lib -lcgic -lm -lssl -lcrypto
AR=ar

HTMDIR=/srv/www/std-root/fm4dd.com/sw/webcert
CGIDIR=/srv/www/std-root/fm4dd.com/sw/webcert/cgi-bin
EXPORTDIR=${CGIDIR}/../export

ALLCGI=buildrequest.cgi genrequest.cgi certsign.cgi certrequest.cgi certverify.cgi help.cgi capolicy.cgi getcert.cgi certstore.cgi certsearch.cgi certexport.cgi certvalidate.cgi p12convert.cgi certrenew.cgi

ALLJS=webcert.js

all: ${ALLCGI}

install: 
	strip ${ALLCGI}
	cp ${ALLJS} ${HTMDIR}
	cp ${ALLCGI} ${CGIDIR}
	@echo ${ALLCGI} installed in ${CGIDIR}.
	@echo "Checking for new export dir needed by certexport.cgi:"; \
	if test -d ${EXPORTDIR}; then echo "...OK. ${EXPORTDIR} exists."; \
	else echo "Please do: mkdir ${EXPORTDIR}."; \
	echo "It should be writeable by the webserver."; fi

clean:
	rm -f *.o *.cgi

buildrequest.cgi: buildrequest.o pagehead.o pagefoot.o handle_error.o
	$(CC) buildrequest.o pagehead.o pagefoot.o -o buildrequest.cgi ${LIBS}

genrequest.cgi: webcert.o genrequest.o pagehead.o pagefoot.o handle_error.o
	$(CC) webcert.o handle_error.o genrequest.o pagehead.o pagefoot.o -o genrequest.cgi ${LIBS}

certsign.cgi: webcert.o pagehead.o pagefoot.o handle_error.o serial.o certsign.o
	$(CC) webcert.o pagehead.o pagefoot.o handle_error.o serial.o certsign.o -o certsign.cgi ${LIBS}

certrequest.cgi: certrequest.o
	$(CC) certrequest.o pagehead.o pagefoot.o -o certrequest.cgi ${LIBS}

certverify.cgi: webcert.o certverify.o
	$(CC) webcert.o certverify.o pagehead.o pagefoot.o handle_error.o -o certverify.cgi ${LIBS}

help.cgi: help.o
	$(CC) help.o pagehead.o pagefoot.o handle_error.o -o help.cgi ${LIBS}

capolicy.cgi: capolicy.o
	$(CC) capolicy.o pagehead.o pagefoot.o handle_error.o -o capolicy.cgi ${LIBS}

getcert.cgi: getcert.o
	$(CC) getcert.o pagehead.o pagefoot.o handle_error.o -o getcert.cgi ${LIBS}

certstore.cgi: certstore.o
	$(CC) certstore.o pagehead.o pagefoot.o handle_error.o -o certstore.cgi ${LIBS}

certsearch.cgi: certsearch.o
	$(CC) certsearch.o pagehead.o pagefoot.o handle_error.o -o certsearch.cgi ${LIBS}

certexport.cgi: webcert.o certexport.o
	$(CC) webcert.o certexport.o pagehead.o pagefoot.o handle_error.o -o certexport.cgi ${LIBS}

certvalidate.cgi: webcert.o certvalidate.o
	$(CC) webcert.o certvalidate.o pagehead.o pagefoot.o handle_error.o -o certvalidate.cgi ${LIBS}

p12convert.cgi: webcert.o p12convert.o
	$(CC) webcert.o p12convert.o pagehead.o pagefoot.o handle_error.o -o p12convert.cgi ${LIBS}

certrenew.cgi: webcert.o certrenew.o
	$(CC) webcert.o certrenew.o pagehead.o pagefoot.o handle_error.o -o certrenew.cgi ${LIBS}
