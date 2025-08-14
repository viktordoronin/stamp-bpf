# TODO: go generate, proper vars and args, 

binaries: cmd/bin/sender cmd/bin/reflector
.PHONY:binaries

cmd/bin/sender: cmd/sender/sender.go internal/bpf/sender/* internal/userspace/*/*
	CGO_ENABLED=0 go build -C ./cmd/sender -o ../bin/

cmd/bin/reflector: cmd/reflector/reflector.go internal/bpf/reflector/* internal/userspace/*/* 
	CGO_ENABLED=0 go build -C ./cmd/reflector -o ../bin/

# TODO: make this not build every time
# TODO: docker save // docker load
teststand: docker/compose.yaml 
	docker compose -f ./docker/compose.yaml build

demo: teststand binaries
	docker compose -f ./docker/compose.yaml up -d
	docker exec -it stamp_sender /home/bin/sender eth0 172.30.0.3
.PHONY: demo

clean:
	docker compose -f ./docker/compose.yaml down -t0
.PHONY:clean
