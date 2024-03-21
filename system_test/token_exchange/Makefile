CERT_DIR := ../cert

.PHONY: login
login: setup
	$(MAKE) -C login

.PHONY: setup
setup: dex

.PHONY: dex
dex:
	$(MAKE) -C dex

.PHONY: logs
logs:
	$(MAKE) -C dex logs

.PHONY: clean terminate
clean terminate:
	$(MAKE) -C dex clean
	$(MAKE) -C login clean
