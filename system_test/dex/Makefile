CERT_DIR := ../cert

.PHONY: dex
dex: dex.yaml
	# wait for kind network
	while true; do if docker network inspect kind; then break; fi; sleep 1; done
	# create a container
	docker create --name dex-server -p 10443:10443 --network kind quay.io/dexidp/dex:v2.21.0 serve /dex.yaml
	# deploy the config
	docker cp $(CERT_DIR)/server.crt dex-server:/
	docker cp $(CERT_DIR)/server.key dex-server:/
	docker cp dex.yaml dex-server:/
	# start the container
	docker start dex-server
	docker logs dex-server

.PHONY: terminate
terminate:
	docker stop dex-server
	docker rm dex-server
