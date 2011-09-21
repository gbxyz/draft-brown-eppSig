all:
	make keys
	make tests
	make clean

keys:
	openssl genrsa -out private.key 2048
	openssl rsa -in private.key -pubout -out public.key

tests:
	php sign.php
	php validate.php

clean:
	rm -fv *key signed.xml
