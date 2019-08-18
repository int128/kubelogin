all: ca1.crt ca1.crt.base64 ca2.crt ca2.crt.base64 ca3.crt ca3.crt.base64

.PHONY: clean
clean:
	-rm -v *.key *.csr *.crt *.base64

%.key:
	openssl genrsa -out $@ 1024

%.csr: %.key
	openssl req \
		-new \
		-key $< \
		-subj "/CN=Hello" \
		-days 3650 \
		-out $@
	openssl req -noout -text -in $@

%.crt: %.csr %.key
	openssl x509 -req \
		-signkey $*.key \
		-in $*.csr \
		-days 3650 \
		-out $@
	openssl x509 -text -in $@

%.crt.base64: %.crt
	base64 -i $< -o $@
