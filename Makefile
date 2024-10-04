lint:
	golangci-lint run

test:
	go test -count=1 ./... -v

build-http:
	go build github.com/xconnio/wireguard-admin-service/cmd/http-service

run-http:
	go run github.com/xconnio/wireguard-admin-service/cmd/http-service

build-docker:
	docker build -t wireguard .

run-docker:
	docker compose up
