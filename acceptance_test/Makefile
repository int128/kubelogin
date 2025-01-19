CLUSTER_NAME := kubelogin-acceptance-test
OUTPUT_DIR := $(CURDIR)/output

KUBECONFIG := $(OUTPUT_DIR)/kubeconfig.yaml
export KUBECONFIG

.PHONY: cluster
cluster:
	# Create a cluster.
	mkdir -p $(OUTPUT_DIR)
	sed -e "s|OIDC_ISSUER_URL|$(OIDC_ISSUER_URL)|" -e "s|OIDC_CLIENT_ID|$(OIDC_CLIENT_ID)|" cluster.yaml > $(OUTPUT_DIR)/cluster.yaml
	kind create cluster --name $(CLUSTER_NAME) --config $(OUTPUT_DIR)/cluster.yaml

	# Set up the access control.
	kubectl create clusterrole cluster-readonly --verb=get,watch,list --resource='*.*'
	kubectl create clusterrolebinding cluster-readonly --clusterrole=cluster-readonly --user=$(YOUR_EMAIL)

	# Set up kubectl.
	kubectl config set-credentials oidc \
		--exec-command=$(CURDIR)/../kubelogin \
		--exec-arg=get-token \
		--exec-arg=--token-cache-dir=$(OUTPUT_DIR)/token-cache \
		--exec-arg=--oidc-issuer-url=$(OIDC_ISSUER_URL) \
		--exec-arg=--oidc-client-id=$(OIDC_CLIENT_ID) \
		--exec-arg=--oidc-extra-scope=email

	# Switch the default user.
	kubectl config set-context --current --user=oidc

	# Show the kubeconfig.
	kubectl config view

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
