all: jws.key

jws.key:
	openssl genrsa -out $@ 1024

.PHONY: clean
clean:
	-rm -v jws.key
