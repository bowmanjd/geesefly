CC = gcc
ifdef BIGENDIAN
ENDIAN = -DBIGENDIAN
else
ENDIAN = 
endif
CFLAGS = -Wall -O2 -fno-strict-aliasing $(ENDIAN)
COMPONENTS = skein.o threefish.o

all: skein_test

skein_test: skein_test.c $(COMPONENTS)
	$(CC) $(CFLAGS) -o skein_test skein_test.c $(COMPONENTS)

clean:
	rm -f *.o skein_test
