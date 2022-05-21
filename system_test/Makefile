CERT_DIR := cert

.PHONY: login
login: setup
	$(MAKE) -C login

.PHONY: setup
setup: dex cluster setup-chrome

.PHONY: dex
dex: cert
	$(MAKE) -C dex

.PHONY: cluster
cluster: cert
	$(MAKE) -C cluster

.PHONY: setup-chrome
setup-chrome: cert
	# add the dex server certificate to the trust store
	certutil -A -d sql:$(HOME)/.pki/nssdb -n dex -i $(CERT_DIR)/ca.crt -t "TC,,"

.PHONY: cert
cert:
	$(MAKE) -C cert

.PHONY: logs
logs:
	$(MAKE) -C cluster logs

.PHONY: terminate
terminate:
	$(MAKE) -C cluster terminate
	$(MAKE) -C dex terminate

.PHONY: clean
clean:
	$(MAKE) -C cert clean
	$(MAKE) -C cluster clean
	$(MAKE) -C dex clean
	$(MAKE) -C login clean
