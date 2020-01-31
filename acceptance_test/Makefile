CLUSTER_NAME := kubelogin-acceptance-test
OUTPUT_DIR := $(CURDIR)/output

KUBECONFIG := $(OUTPUT_DIR)/kubeconfig.yaml
export KUBECONFIG

.PHONY: all
all: build setup test

.PHONY: clean
clean:
	-rm -r $(OUTPUT_DIR)

# build binaries for the container
.PHONY: build
build: $(OUTPUT_DIR)/kubelogin_linux_amd64 $(OUTPUT_DIR)/kubelogin_acceptance_test_linux_amd64
$(OUTPUT_DIR)/kubelogin_linux_amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $@ ..
$(OUTPUT_DIR)/kubelogin_acceptance_test_linux_amd64: $(wildcard *.go)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o $@ .

# create a Kubernetes cluster with Dex
.PHONY:
setup: create-cluster deploy

.PHONY: create-cluster
create-cluster:
	kind create cluster --name $(CLUSTER_NAME) --config cluster.yaml
delete-cluster:
	kind delete cluster --name $(CLUSTER_NAME)

.PHONY: deploy
deploy: $(OUTPUT_DIR)/server.crt $(OUTPUT_DIR)/server.key
	kubectl apply -f dex.yaml
	kubectl -n dex create secret tls dex.tls --cert=$(OUTPUT_DIR)/server.crt --key=$(OUTPUT_DIR)/server.key
	kubectl -n dex rollout status deployment server
	kubectl apply -f role.yaml

$(OUTPUT_DIR)/ca.key:
	docker cp $(CLUSTER_NAME)-control-plane:/etc/kubernetes/pki/ca.key $@
$(OUTPUT_DIR)/ca.crt:
	docker cp $(CLUSTER_NAME)-control-plane:/etc/kubernetes/pki/ca.crt $@
$(OUTPUT_DIR)/server.key:
	openssl genrsa -out $@ 2048
$(OUTPUT_DIR)/server.csr: openssl.cnf $(OUTPUT_DIR)/server.key
	openssl req -new -key $(OUTPUT_DIR)/server.key -out $@ -subj "/CN=kubelogin-acceptance-test-control-plane" -config openssl.cnf
	#openssl req -noout -text -in $@
$(OUTPUT_DIR)/server.crt: openssl.cnf $(OUTPUT_DIR)/server.csr $(OUTPUT_DIR)/ca.crt $(OUTPUT_DIR)/ca.key
	openssl x509 -req -in $(OUTPUT_DIR)/server.csr -CA $(OUTPUT_DIR)/ca.crt -CAkey $(OUTPUT_DIR)/ca.key -CAcreateserial -out $@ -sha256 -days 10 -extensions v3_req -extfile openssl.cnf
	#openssl x509 -text -in $@

# run the test on a container:
.PHONY: test
test: docker-run

# - enable host network to access Dex via the node port
# - add /etc/hosts to access Dex
DOCKER_RUN_FLAGS := \
	--net host \
	--add-host kubelogin-acceptance-test-control-plane:127.0.0.1

.PHONY: docker-build
docker-build: build
	docker build -t kubelogin-acceptance-test .
.PHONY: docker-run
docker-run: docker-build
	docker run --rm $(DOCKER_RUN_FLAGS) kubelogin-acceptance-test
.PHONY: docker-shell
docker-shell: docker-build
	docker run -it --rm $(DOCKER_RUN_FLAGS) kubelogin-acceptance-test /bin/sh
