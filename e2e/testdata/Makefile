.PHONY: clean

all: authserver.crt authserver-ca.crt

clean:
	rm -v authserver*

authserver-ca.key:
	openssl genrsa -out $@ 1024

authserver-ca.csr: openssl.cnf authserver-ca.key
	openssl req -config openssl.cnf \
		-new \
		-key authserver-ca.key \
		-subj "/CN=Hello CA" \
		-out $@
	openssl req -noout -text -in $@

authserver-ca.crt: authserver-ca.csr authserver-ca.key
	openssl x509 -req \
		-signkey authserver-ca.key \
		-in authserver-ca.csr \
		-out $@
	openssl x509 -text -in $@

authserver.key:
	openssl genrsa -out $@ 1024

authserver.csr: openssl.cnf authserver.key
	openssl req -config openssl.cnf \
		-new \
		-key authserver.key \
		-subj "/CN=localhost" \
		-out $@
	openssl req -noout -text -in $@

authserver.crt: openssl.cnf authserver.csr authserver-ca.key authserver-ca.crt
	rm -fr ./CA
	mkdir -p ./CA
	touch CA/index.txt
	touch CA/index.txt.attr
	echo 00 > CA/serial
	openssl ca -config openssl.cnf \
		-extensions v3_req \
		-batch \
		-cert authserver-ca.crt \
		-keyfile authserver-ca.key \
		-in authserver.csr \
		-out $@
	openssl x509 -text -in $@
