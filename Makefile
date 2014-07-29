CC_FLAGS=-Wall #-O3

aez_ni_bm: aez/aez_ni_bm.c aez-core.o aez-mac.o aez-cipher.o aez-crypt.o rijndael-alg-fst.o 
	gcc $(CC_FLAGS) aez/aez_ni_bm.c aez-core.o aez-mac.o aez-cipher.o aez-crypt.o rijndael-alg-fst.o -std=c99 -maes -mssse3 -o aez_ni_bm

aez_bm: aez/aez_bm.c aez-core.o aez-mac.o aez-cipher.o aez-crypt.o rijndael-alg-fst.o
	gcc $(CC_FLAGS) aez/aez_bm.c aez-core.o aez-mac.o aez-cipher.o aez-crypt.o rijndael-alg-fst.o -o aez_bm

aeztest: aez/aeztest.c aez-core.o aez-mac.o aez-cipher.o aez-crypt.o rijndael-alg-fst.o 
	gcc $(CC_FLAGS) aez/aeztest.c aez-core.o aez-mac.o aez-cipher.o aez-crypt.o rijndael-alg-fst.o -o aeztest

rijndael-alg-fst.o: aez/rijndael-alg-fst.h aez/rijndael-alg-fst.c
	gcc $(CC_FLAGS) -c aez/rijndael-alg-fst.c 

oaep-rsa: oaep-rsa.c oaep.o rsa.o sha1.o util.o 
	gcc $(CC_FLAGS) -o oaep-rsa oaep-rsa.c oaep.o sha1.o rsa.o util.o -lgmp

aez-crypt.o: aez/aez.h aez/aez-crypt.c  
	gcc $(CC_FLAGS) -c aez/aez-crypt.c 

aez-cipher.o: aez/aez.h aez/aez-cipher.c  
	gcc $(CC_FLAGS) -c aez/aez-cipher.c 

aez-core.o: aez/aez.h aez/aez-core.c  
	gcc $(CC_FLAGS) -c aez/aez-core.c 

aez-mac.o: aez/aez.h aez/aez-mac.c  
	gcc $(CC_FLAGS) -c aez/aez-mac.c 

oaep.o: rsa/oaep.h rsa/oaep.c rsa.o sha1.o
	gcc $(CC_FLAGS) -c rsa/oaep.c -lgmp

rsa.o: rsa/rsa.h rsa/rsa.c util.o
	gcc $(CC_FLAGS) -c rsa/rsa.c -lgmp

sha1.o: hash/sha1.h hash/sha1.c
	gcc $(CC_FLAGS) -c hash/sha1.c

chacha.o: cipher/chacha.h cipher/chacha.c portable.h
	gcc $(CC_FLAGS) -c cipher/chacha.c

keygen.o: misc/keygen.h misc/keygen.c portable.h
	gcc $(CC_FLAGS) -c misc/keygen.c

util.o: misc/util.h misc/util.c 
	gcc $(CC_FLAGS) -c misc/util.c

all: oaep-rsa oaeptest rsatest sha1test chachatest

clean: 
	rm -f *.o *test oaep-rsa aez_bm aez_ni_bm

# A couple tests ... 
do: oaep-rsa
	./oaep-rsa --gen 1024
	./oaep-rsa --encrypt -i papers/rfc3447_oaep.html -o cipher
	./oaep-rsa --decrypt -i cipher -o message;
	diff message papers/rfc3447_oaep.html
	du -h cipher papers/rfc3447_oaep.html

did: oaep-rsa
	./oaep-rsa --gen 512
	./oaep-rsa --encrypt -i papers/message.jpg -o cipher
	./oaep-rsa --decrypt -i cipher -o plaintext.jpg
	du -h cipher plaintext.jpg papers/message.jpg

oaeptest: rsa/oaeptest.c oaep.o rsa.o sha1.o util.o 
	gcc $(CC_FLAGS) -o oaeptest rsa/oaeptest.c oaep.o sha1.o rsa.o util.o -lgmp

rsatest: rsa/rsatest.c rsa.o util.o 
	gcc $(CC_FLAGS) -o rsatest rsa/rsatest.c rsa.o util.o -lgmp

chachatest: cipher/chachatest.c chacha.o keygen.o
	gcc $(CC_FLAGS) -o chachatest cipher/chachatest.c chacha.o keygen.o -lgmp

sha1test: hash/sha1test.c sha1.o
	gcc $(CC_FLAGS) -o sha1test hash/sha1test.c sha1.o 

