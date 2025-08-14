# TODO: go generate, proper vars and args, 

binaries: sender reflector
.PHONY:binaries

sender: cmd/bin/sender
reflector: cmd/bin/reflector
.PHONY:sender reflector

cmd/bin/sender: cmd/sender/sender.go 
	CGO_ENABLED=0 go build -C ./cmd/sender -o ../bin/
cmd/bin/reflector: cmd/reflector/reflector.go 
	CGO_ENABLED=0 go build -C ./cmd/reflector -o ../bin/

# TODO: make this not build every time
teststand: $(wildcard docker/*) $(wildcard docker/*/*) binaries
	docker compose -f ./docker/compose.yaml build

demo: teststand
	docker compose -f ./docker/compose.yaml up -d
	docker exec -it stamp_sender /home/sender eth0 172.30.0.3

clean:
	docker compose -f ./docker/compose.yaml down -t0
.PHONY:clean
