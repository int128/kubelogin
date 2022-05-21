CLUSTER_NAME := kubelogin-system-test
CERT_DIR := ../cert

KUBECONFIG := kubeconfig.yaml
export KUBECONFIG

.PHONY: cluster
cluster:
	cp $(CERT_DIR)/ca.crt /tmp/kubelogin-system-test-dex-ca.crt
	kind create cluster --name $(CLUSTER_NAME) --config cluster.yaml
	# add the Dex container IP to /etc/hosts
	docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' dex-server | sed -e 's,$$, dex-server,' | \
		docker exec -i $(CLUSTER_NAME)-control-plane tee -a /etc/hosts
	# wait for kube-apiserver oidc initialization
	# (oidc authenticator will retry oidc discovery every 10s)
	sleep 10
	# add the cluster role
	kubectl create clusterrole cluster-readonly --verb=get,watch,list --resource='*.*'
	kubectl create clusterrolebinding cluster-readonly --clusterrole=cluster-readonly --user=admin@example.com

.PHONY: logs
logs:
	kubectl -n kube-system logs kube-apiserver-kubelogin-system-test-control-plane

.PHONY: terminate
terminate:
	kind delete cluster --name $(CLUSTER_NAME)
