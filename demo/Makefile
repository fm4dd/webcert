CC=gcc
CFLAGS= -O3 -Wall -g -I/home/openssl/include -I/home/include
LIBS= -L/home/lib -L/home/openssl/lib -lssl -lcrypto
AR=ar

all: test_serial test_gendsa test_genrsa test_genreq certsort

clean:
	rm -f *.o test_serial test_gendsa test_genrsa test_genreq certsort

test_serial: serial2.o test_serial.o
	$(CC) ${LIBS} serial2.o test_serial.o -o test_serial

test_gendsa: test_gendsa.o
	$(CC) ${LIBS} test_gendsa.o -o test_gendsa

test_genrsa: test_genrsa.o
	$(CC) ${LIBS} test_genrsa.o -o test_genrsa

test_genreq: test_genreq.o
	$(CC) ${LIBS} test_genreq.o -o test_genreq

certsort: certsort.o
	$(CC) ${LIBS} certsort.o -o certsort
