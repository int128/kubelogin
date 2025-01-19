CERT_DIR := cert

.PHONY: test-with-dbus-session
test-with-dbus-session:
	dbus-run-session -- $(MAKE) test

.PHONY: test
test: dex cluster setup-chrome setup-keyring
	$(MAKE) -C login

.PHONY: dex
dex: cert
	$(MAKE) -C dex

.PHONY: cluster
cluster: cert
	$(MAKE) -C cluster

# Add the server certificate of dex to the trust store for Chrome.
.PHONY: setup-chrome
setup-chrome: cert
	mkdir -p $(HOME)/.pki/nssdb
	certutil -A -d sql:$(HOME)/.pki/nssdb -n dex -i $(CERT_DIR)/ca.crt -t "TC,,"

# Start gnome-keyring-daemon.
# https://github.com/zalando/go-keyring/issues/45
.PHONY: setup-keyring
setup-keyring:
	echo password | gnome-keyring-daemon --unlock

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
