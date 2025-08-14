# TODO: proper vars instead of this mess

binaries: cmd/bin/sender cmd/bin/reflector
.PHONY:binaries

cmd/bin/sender: cmd/sender/sender.go internal/bpf/sender/* internal/userspace/*/* 
	CGO_ENABLED=0 go build -C ./cmd/sender -o ../bin/

cmd/bin/reflector: cmd/reflector/reflector.go internal/bpf/reflector/* internal/userspace/*/* 
	CGO_ENABLED=0 go build -C ./cmd/reflector -o ../bin/

# FIXME
internal/bpf/sender/sender_x86_bpfel.go internal/bpf/reflector/reflector_x86_bpfel.go &: internal/bpf/*
	go generate ./internal/bpf

demo: binaries clean
	docker compose -f ./docker/demo/compose.yaml up -d -t0
	docker exec stamp_reflector tc qdisc add dev eth0 root netem delay 100ms
	docker exec stamp_sender tc qdisc add dev eth0 root netem delay 50ms
	docker exec -d stamp_reflector /home/bin/reflector eth0
	docker exec stamp_sender /home/bin/sender eth0 172.30.0.3 -c 10
	docker compose -f ./docker/demo/compose.yaml down -t0
.PHONY: demo teststand

clean:
	docker compose -f ./docker/demo/compose.yaml down -t0
.PHONY:clean
