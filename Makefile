CC = gcc
ifdef BIGENDIAN
ENDIAN = -DBIGENDIAN
else
ENDIAN = 
endif
CFLAGS = -Wall -O2 $(ENDIAN)
COMPONENTS = skein.o threefish.o

all: skein_test

skein_test: skein_test.c $(COMPONENTS)
	$(CC) $(CFLAGS) -fno-strict-aliasing -o skein_test skein_test.c $(COMPONENTS)

clean:
	rm -f *.o skein_test
