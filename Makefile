CC = gcc
CFLAGS = -Wall -O2
COMPONENTS = skein.c threefish.c

all: skein_test

skein_test: skein_test.c
	$(CC) $(CFLAGS) -fno-strict-aliasing -o skein_test skein_test.c $(COMPONENTS)

clean:
	rm -f *.o skein_test
