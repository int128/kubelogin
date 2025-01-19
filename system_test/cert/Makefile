.PHONY: all
all: ca.key ca.crt server.key server.crt

ca.key:
	openssl genrsa -out $@ 2048
ca.csr: ca.key
	openssl req -new -key ca.key -out $@ -subj "/CN=dex-ca" -config openssl.cnf
ca.crt: ca.key ca.csr
	openssl x509 -req -in ca.csr -signkey ca.key -out $@ -days 10
server.key:
	openssl genrsa -out $@ 2048
server.csr: openssl.cnf server.key
	openssl req -new -key server.key -out $@ -subj "/CN=dex-server" -config openssl.cnf
server.crt: openssl.cnf server.csr ca.crt ca.key
	openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $@ -sha256 -days 10 -extensions v3_req -extfile openssl.cnf

.PHONY: clean
clean:
	-rm ca.* server.*
