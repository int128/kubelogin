EXPIRY := 3650
OUTPUT_DIR := testdata
TARGETS := ca.key
TARGETS += ca.crt
TARGETS += server.key
TARGETS += server.crt

.PHONY: all
all: $(TARGETS)

ca.key:
	openssl genrsa -out $@ 2048
ca.csr: ca.key
	openssl req -new -key ca.key -out $@ -subj "/CN=hello-ca" -config openssl.cnf
ca.crt: ca.key ca.csr
	openssl x509 -req -in ca.csr -signkey ca.key -out $@ -days $(EXPIRY)
server.key:
	openssl genrsa -out $@ 2048
server.csr: openssl.cnf server.key
	openssl req -new -key server.key -out $@ -subj "/CN=localhost" -config openssl.cnf
server.crt: openssl.cnf server.csr ca.crt ca.key
	openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $@ -sha256 -days $(EXPIRY) -extensions v3_req -extfile openssl.cnf

.PHONY: clean
clean:
	-rm -v $(TARGETS)
