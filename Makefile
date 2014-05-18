CC_FLAGS=-Wall #-O3

test: chachatest.c chacha.o keygen.o
	gcc $(CC_FLAGS) -o test chachatest.c chacha.o keygen.o -lgmp

oaep-rsa: oaep-rsa.c oaep.o rsa.o sha1.o util.o 
	gcc $(CC_FLAGS) -o oaep-rsa oaep-rsa.c oaep.o sha1.o rsa.o util.o -lgmp

oaep.o: oaep.h oaep.c rsa.o sha1.o
	gcc $(CC_FLAGS) -c oaep.c -lgmp

rsa.o: rsa.h rsa.c util.o
	gcc $(CC_FLAGS) -c rsa.c -lgmp

sha1.o: sha1.h sha1.c
	gcc $(CC_FLAGS) -c sha1.c

chacha.o: chacha.h chacha.c portable.h
	gcc $(CC_FLAGS) -c chacha.c

keygen.o: keygen.h keygen.c portable.h
	gcc $(CC_FLAGS) -c keygen.c

util.o: util.h util.c 
	gcc $(CC_FLAGS) -c util.c

clean: 
	rm -f *.o *test oaep-rsa

# A couple tests ... 
do: oaep-rsa
	./oaep-rsa --gen 1024
	./oaep-rsa --encrypt -i ref/rfc3447_oaep.html -o cipher
	./oaep-rsa --decrypt -i cipher -o message;
	diff message ref/rfc3447_oaep.html
	du -h cipher ref/rfc3447_oaep.html

did: oaep-rsa
	./oaep-rsa --gen 512
	./oaep-rsa --encrypt -i ref/message.jpg -o cipher
	./oaep-rsa --decrypt -i cipher -o plaintext.jpg
	du -h cipher plaintext.jpg ref/message.jpg

oaeptest: oaeptest.c oaep.o rsa.o sha1.o util.o 
	gcc $(CC_FLAGS) -o oaeptest oaeptest.c oaep.o sha1.o rsa.o util.o -lgmp

rsatest: rsatest.c rsa.o util.o 
	gcc $(CC_FLAGS) -o rsatest rsatest.c rsa.o util.o -lgmp

sha1test: sha1test.c sha1.o
	gcc $(CC_FLAGS) -o sha1test sha1test.c sha1.o 

