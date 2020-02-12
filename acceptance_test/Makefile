CLUSTER_NAME := kubelogin-acceptance-test
OUTPUT_DIR := $(CURDIR)/output

PATH := $(PATH):$(OUTPUT_DIR)/bin
export PATH
KUBECONFIG := $(OUTPUT_DIR)/kubeconfig.yaml
export KUBECONFIG

# run the login script instead of opening chrome
BROWSER := $(OUTPUT_DIR)/bin/chromelogin
export BROWSER

.PHONY: test
test: build
	# see the setup instruction
	kubectl oidc-login setup \
		--oidc-issuer-url=https://dex-server:10443/dex \
		--oidc-client-id=YOUR_CLIENT_ID \
		--oidc-client-secret=YOUR_CLIENT_SECRET \
		--oidc-extra-scope=email \
		--certificate-authority=$(OUTPUT_DIR)/ca.crt
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
		--exec-arg=--certificate-authority=$(OUTPUT_DIR)/ca.crt
	# make sure we can access the cluster
	kubectl --user=oidc cluster-info
	# switch the current context
	kubectl config set-context --current --user=oidc
	# make sure we can access the cluster
	kubectl cluster-info

.PHONY: setup
setup: build dex cluster setup-chrome

.PHONY: setup-chrome
setup-chrome: $(OUTPUT_DIR)/ca.crt
	# add the dex server certificate to the trust store
	mkdir -p ~/.pki/nssdb
	cd ~/.pki/nssdb && certutil -A -d sql:. -n dex -i $(OUTPUT_DIR)/ca.crt -t "TC,,"

# build binaries
.PHONY: build
build: $(OUTPUT_DIR)/bin/kubectl-oidc_login $(OUTPUT_DIR)/bin/chromelogin
$(OUTPUT_DIR)/bin/kubectl-oidc_login:
	go build -o $@ ..
$(OUTPUT_DIR)/bin/chromelogin: chromelogin/main.go
	go build -o $@ ./chromelogin

# create a Dex server
.PHONY: dex
dex: $(OUTPUT_DIR)/server.crt $(OUTPUT_DIR)/server.key
	docker create --name dex-server -p 10443:10443 quay.io/dexidp/dex:v2.21.0 serve /dex.yaml
	docker cp $(OUTPUT_DIR)/server.crt dex-server:/
	docker cp $(OUTPUT_DIR)/server.key dex-server:/
	docker cp dex.yaml dex-server:/
	docker start dex-server
	docker logs dex-server

$(OUTPUT_DIR)/ca.key:
	mkdir -p $(OUTPUT_DIR)
	openssl genrsa -out $@ 2048
$(OUTPUT_DIR)/ca.csr: $(OUTPUT_DIR)/ca.key
	openssl req -new -key $(OUTPUT_DIR)/ca.key -out $@ -subj "/CN=dex-ca" -config openssl.cnf
$(OUTPUT_DIR)/ca.crt: $(OUTPUT_DIR)/ca.key $(OUTPUT_DIR)/ca.csr
	openssl x509 -req -in $(OUTPUT_DIR)/ca.csr -signkey $(OUTPUT_DIR)/ca.key -out $@ -days 10
$(OUTPUT_DIR)/server.key:
	mkdir -p $(OUTPUT_DIR)
	openssl genrsa -out $@ 2048
$(OUTPUT_DIR)/server.csr: openssl.cnf $(OUTPUT_DIR)/server.key
	openssl req -new -key $(OUTPUT_DIR)/server.key -out $@ -subj "/CN=dex-server" -config openssl.cnf
$(OUTPUT_DIR)/server.crt: openssl.cnf $(OUTPUT_DIR)/server.csr $(OUTPUT_DIR)/ca.crt $(OUTPUT_DIR)/ca.key
	openssl x509 -req -in $(OUTPUT_DIR)/server.csr -CA $(OUTPUT_DIR)/ca.crt -CAkey $(OUTPUT_DIR)/ca.key -CAcreateserial -out $@ -sha256 -days 10 -extensions v3_req -extfile openssl.cnf

# create a Kubernetes cluster
.PHONY: cluster
cluster: dex create-cluster
	# add the Dex container IP to /etc/hosts of kube-apiserver
	docker inspect -f '{{.NetworkSettings.IPAddress}}' dex-server | sed -e 's,$$, dex-server,' | \
		kubectl -n kube-system exec -i kube-apiserver-$(CLUSTER_NAME)-control-plane -- tee -a /etc/hosts
	# wait for kube-apiserver oidc initialization
	# (oidc authenticator will retry oidc discovery every 10s)
	sleep 10

.PHONY: create-cluster
create-cluster: $(OUTPUT_DIR)/ca.crt
	cp $(OUTPUT_DIR)/ca.crt /tmp/kubelogin-acceptance-test-dex-ca.crt
	kind create cluster --name $(CLUSTER_NAME) --config cluster.yaml
	kubectl apply -f role.yaml

# clean up the resources
.PHONY: clean
clean:
	-rm -r $(OUTPUT_DIR)
.PHONY: delete-cluster
delete-cluster:
	kind delete cluster --name $(CLUSTER_NAME)
.PHONY: delete-dex
delete-dex:
	docker stop dex-server
	docker rm dex-server
