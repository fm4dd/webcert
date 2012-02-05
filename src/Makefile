CC=gcc
CFLAGS= -O3 -Wall -g
LIBS= -L/home/lib -lcgic -lm -lssl -lcrypto
AR=ar

CGIDIR=/srv/www/std-root/frank4dd.com/sw/webcert/cgi-bin
EXPORTDIR=${CGIDIR}/../export

ALLCGI=buildrequest.cgi genrequest.cgi certsign.cgi certrequest.cgi certverify.cgi help.cgi capolicy.cgi about.cgi getcert.cgi certstore.cgi certsearch.cgi certexport.cgi

all: ${ALLCGI}

install: 
	strip ${ALLCGI}
	cp ${ALLCGI} ${CGIDIR}
	@echo ${ALLCGI} installed in ${CGIDIR}.
	@echo "Checking for new export dir needed by certexport.cgi:"; \
	if test -d ${EXPORTDIR}; then echo "...OK. ${EXPORTDIR} exists."; \
	else echo "Please do: mkdir ${EXPORTDIR}."; \
	echo "It should be writeable by the webserver."; fi

clean:
	rm -f *.o *.cgi

buildrequest.cgi: buildrequest.o pagehead.o pagefoot.o handle_error.o
	$(CC) ${LIBS} buildrequest.o pagehead.o pagefoot.o -o buildrequest.cgi

genrequest.cgi: genrequest.o pagehead.o pagefoot.o handle_error.o
	$(CC) ${LIBS} handle_error.o genrequest.o pagehead.o pagefoot.o -o genrequest.cgi

certsign.cgi: pagehead.o pagefoot.o handle_error.o serial.o certsign.o
	$(CC) ${LIBS} pagehead.o pagefoot.o handle_error.o serial.o certsign.o -o certsign.cgi

certrequest.cgi: certrequest.o
	$(CC) ${LIBS} certrequest.o pagehead.o pagefoot.o -o certrequest.cgi

certverify.cgi: certverify.o
	$(CC) ${LIBS} certverify.o pagehead.o pagefoot.o handle_error.o -o certverify.cgi

help.cgi: help.o
	$(CC) ${LIBS} help.o pagehead.o pagefoot.o handle_error.o -o help.cgi

capolicy.cgi: capolicy.o
	$(CC) ${LIBS} capolicy.o pagehead.o pagefoot.o handle_error.o -o capolicy.cgi

about.cgi: about.o
	$(CC) ${LIBS} about.o pagehead.o pagefoot.o handle_error.o -o about.cgi

getcert.cgi: getcert.o
	$(CC) ${LIBS} getcert.o pagehead.o pagefoot.o handle_error.o -o getcert.cgi

certstore.cgi: certstore.o
	$(CC) ${LIBS} certstore.o pagehead.o pagefoot.o handle_error.o -o certstore.cgi

certsearch.cgi: certsearch.o
	$(CC) ${LIBS} certsearch.o pagehead.o pagefoot.o handle_error.o -o certsearch.cgi

certexport.cgi: certexport.o
	$(CC) ${LIBS} certexport.o pagehead.o pagefoot.o handle_error.o -o certexport.cgi
