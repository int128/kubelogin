.PHONY: clean

all: server.crt ca.crt

clean:
	rm -v ca.* server.*

ca.key:
	openssl genrsa -out $@ 1024

ca.csr: openssl.cnf ca.key
	openssl req -config openssl.cnf \
		-new \
		-key ca.key \
		-subj "/CN=Hello CA" \
		-out $@
	openssl req -noout -text -in $@

ca.crt: ca.csr ca.key
	openssl x509 -req \
		-signkey ca.key \
		-in ca.csr \
		-out $@
	openssl x509 -text -in $@

server.key:
	openssl genrsa -out $@ 1024

server.csr: openssl.cnf server.key
	openssl req -config openssl.cnf \
		-new \
		-key server.key \
		-subj "/CN=localhost" \
		-out $@
	openssl req -noout -text -in $@

server.crt: openssl.cnf server.csr ca.key ca.crt
	rm -fr ./CA
	mkdir -p ./CA
	touch CA/index.txt
	touch CA/index.txt.attr
	echo 00 > CA/serial
	openssl ca -config openssl.cnf \
		-extensions v3_req \
		-batch \
		-cert ca.crt \
		-keyfile ca.key \
		-in server.csr \
		-out $@
	openssl x509 -text -in $@
