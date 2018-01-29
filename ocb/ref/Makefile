# Add to to the end of cc when building on Mac.
mac_cppflags = -I/usr/local/opt/openssl/include
cc = gcc -Wall -ansi -fpic -std=c11 $(mac_cppflags)
lflags = -lcrypto

all: ocb.c
	$(cc) ocb.c -o ocb_ref $(lflags)
