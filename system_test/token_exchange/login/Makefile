CERT_DIR := ../../cert

BIN_DIR := $(PWD)/bin
PATH := $(PATH):$(BIN_DIR)
export PATH

KUBECONFIG := ../../cluster/kubeconfig.yaml
export KUBECONFIG

token.json: build
	$(BIN_DIR)/kubectl-oidc_login \
		get-token \
		--grant-type=token-exchange \
		--token-exchange-subject-token=ID_TOKEN \
		--token-exchange-subject-token-type=id-token \
		--oidc-issuer-url=https://dex-server:10443/dex \
		--oidc-client-id=YOUR_CLIENT_ID \
		--oidc-client-secret=YOUR_CLIENT_SECRET \
		--oidc-extra-scope="email,groups,openid,profile,federated:id" \
		--certificate-authority=$(CERT_DIR)/ca.crt \
			| jq -r '.status.token' | jq -r -R 'split(".") | .[1] | @base64d | fromjson' > $@

.PHONY: test
test: build token.json
	kubectl config set-credentials oidc \
		--exec-api-version=client.authentication.k8s.io/v1beta1 \
		--exec-command=kubectl \
		--exec-arg=oidc-login \
		--exec-arg=get-token \
		--exec-arg=--grant-type=token-exchange \
		--exec-arg=--token-exchange-subject-token=ID_TOKEN \
		--exec-arg=--token-exchange-subject-token-type=id-token \
		--exec-arg=--oidc-issuer-url=https://dex-server:10443/dex \
		--exec-arg=--oidc-client-id=YOUR_CLIENT_ID \
		--exec-arg=--oidc-client-secret=YOUR_CLIENT_SECRET \
		--exec-arg=--oidc-extra-scope='email' \
		--exec-arg=--oidc-extra-scope='groups' \
		--exec-arg=--oidc-extra-scope='openid' \
		--exec-arg=--oidc-extra-scope='profile' \
		--exec-arg=--oidc-extra-scope='federated:id' \
		--exec-arg=--certificate-authority=$(CERT_DIR)/ca.crt

	kubectl create clusterrolebinding cluster-readonly-gh --clusterrole=cluster-readonly \
		--user="$$(jq -r .email token.json)"

	# make sure we can access the cluster
	kubectl --user=oidc cluster-info

.PHONY: build
build: $(BIN_DIR)/kubectl-oidc_login

$(BIN_DIR)/kubectl-oidc_login:
	go build -o $@ ../../../

.PHONY: clean
clean:
	-rm -r $(BIN_DIR)
	-rm -f token.json
