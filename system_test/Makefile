CERT_DIR := cert

.PHONY: authorization_code
authorization_code: cluster setup-chrome
	$(MAKE) -C $@

.PHONY: token_exchange
token_exchange: cluster
	$(MAKE) -C $@

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

.PHONY: clean terminate
clean terminate:
	$(MAKE) -C cert clean
	$(MAKE) -C cluster clean
	$(MAKE) -C authorization_code clean
	$(MAKE) -C token_exchange clean
