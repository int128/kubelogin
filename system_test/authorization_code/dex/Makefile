CERT_DIR := ../../cert

# Needed at time of writing because token-exchange is in `main`, but not in a release yet.
DEX_REPO := ghcr.io/dexidp/dex
DEX_VERSION := latest-distroless@sha256:d6659a84bdd5d8e6c908ff899d08f910cafe5e6c56c4a974c7c9223988c90b79

# DEX_REPO := quay.io/dexidp/dex
# DEX_VERSION := v2.37.0

.PHONY: dex
dex: dex.yaml
	# wait for kind network
	while true; do if docker network inspect kind; then break; fi; sleep 1; done
	# create a container
	docker create --name dex-server -p 10443:10443 --network kind $(DEX_REPO):$(DEX_VERSION) dex serve /dex.yaml
	# deploy the config
	docker cp $(CERT_DIR)/server.crt dex-server:/
	docker cp $(CERT_DIR)/server.key dex-server:/
	docker cp dex.yaml dex-server:/
	# start the container
	docker start dex-server
	docker logs dex-server

.PHONY: logs
logs:
	docker logs dex-server

.PHONY: terminate clean
terminate clean:
	docker stop dex-server
	docker rm dex-server
