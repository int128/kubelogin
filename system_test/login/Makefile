CERT_DIR := ../cert

BIN_DIR := $(PWD)/bin
PATH := $(PATH):$(BIN_DIR)
export PATH

KUBECONFIG := ../cluster/kubeconfig.yaml
export KUBECONFIG

.PHONY: test
test: build
	# see the setup instruction
	kubectl oidc-login setup \
		--oidc-issuer-url=https://dex-server:10443/dex \
		--oidc-client-id=YOUR_CLIENT_ID \
		--oidc-client-secret=YOUR_CLIENT_SECRET \
		--oidc-extra-scope=email \
		--certificate-authority=$(CERT_DIR)/ca.crt \
		--browser-command=$(BIN_DIR)/chromelogin
	# set up the kubeconfig
	kubectl config set-credentials oidc \
		--exec-api-version=client.authentication.k8s.io/v1beta1 \
		--exec-command=kubectl \
		--exec-arg=oidc-login \
		--exec-arg=get-token \
		--exec-arg=--oidc-issuer-url=https://dex-server:10443/dex \
		--exec-arg=--oidc-client-id=YOUR_CLIENT_ID \
		--exec-arg=--oidc-client-secret=YOUR_CLIENT_SECRET \
		--exec-arg=--oidc-extra-scope=email \
		--exec-arg=--certificate-authority=$(CERT_DIR)/ca.crt \
		--exec-arg=--browser-command=$(BIN_DIR)/chromelogin
	# make sure we can access the cluster
	kubectl --user=oidc cluster-info

.PHONY: build
build: $(BIN_DIR)/kubectl-oidc_login $(BIN_DIR)/chromelogin

$(BIN_DIR)/kubectl-oidc_login:
	go build -o $@ ../../

$(BIN_DIR)/chromelogin: $(wildcard chromelogin/*.go)
	go build -o $@ ./chromelogin

.PHONY: clean
clean:
	-rm -r $(BIN_DIR)
