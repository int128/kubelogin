CLUSTER_NAME := kubelogin-acceptance-test
OUTPUT_DIR := $(CURDIR)/output

KUBECONFIG := $(OUTPUT_DIR)/kubeconfig.yaml
export KUBECONFIG

# create a Kubernetes cluster
.PHONY: cluster
cluster:
	# create a cluster
	mkdir -p $(OUTPUT_DIR)
	sed -e "s|OIDC_ISSUER_URL|$(OIDC_ISSUER_URL)|" -e "s|OIDC_CLIENT_ID|$(OIDC_CLIENT_ID)|" cluster.yaml > $(OUTPUT_DIR)/cluster.yaml
	kind create cluster --name $(CLUSTER_NAME) --config $(OUTPUT_DIR)/cluster.yaml
	# set up access control
	kubectl create clusterrole cluster-readonly --verb=get,watch,list --resource='*.*'
	kubectl create clusterrolebinding cluster-readonly --clusterrole=cluster-readonly --user=$(YOUR_EMAIL)
	# set up kubectl
	kubectl config set-credentials oidc \
		--exec-api-version=client.authentication.k8s.io/v1beta1 \
		--exec-command=$(CURDIR)/../kubelogin \
		--exec-arg=get-token \
		--exec-arg=--token-cache-dir=$(OUTPUT_DIR)/token-cache \
		--exec-arg=--oidc-issuer-url=$(OIDC_ISSUER_URL) \
		--exec-arg=--oidc-client-id=$(OIDC_CLIENT_ID) \
		--exec-arg=--oidc-client-secret=$(OIDC_CLIENT_SECRET) \
		--exec-arg=--oidc-extra-scope=email
	# switch the default user
	kubectl config set-context --current --user=oidc

# clean up the resources
.PHONY: clean
clean:
	-rm -r $(OUTPUT_DIR)
.PHONY: delete-cluster
delete-cluster:
	kind delete cluster --name $(CLUSTER_NAME)

.PHONY: check
check:
	docker version
	kind version
	kubectl version --client
