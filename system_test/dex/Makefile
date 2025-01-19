CERT_DIR := ../cert

.PHONY: dex
dex: dex.yaml
	# Wait for kind network.
	until docker network inspect kind; do sleep 1; done

	# Create a container.
	docker create -q --name dex-server -p 10443:10443 --network kind ghcr.io/dexidp/dex:v2.39.0 dex serve /dex.yaml

	# Deploy the config.
	docker cp $(CERT_DIR)/server.crt dex-server:/
	docker cp $(CERT_DIR)/server.key dex-server:/
	docker cp dex.yaml dex-server:/

	# Start the container.
	docker start dex-server
	docker logs dex-server

.PHONY: terminate
terminate:
	docker stop dex-server
	docker rm dex-server
