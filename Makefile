# TODO: proper vars instead of this mess

binaries: cmd/bin/sender 
.PHONY:binaries

cmd/bin/sender: cmd/sender/sender.go internal/bpf/sender/* internal/userspace/*/* 
	CGO_ENABLED=0 go build -C ./cmd/sender -o ../bin/

cmd/bin/reflector: cmd/reflector/reflector.go internal/bpf/reflector/* internal/userspace/*/* 
	CGO_ENABLED=0 go build -C ./cmd/reflector -o ../bin/

bpf: internal/bpf/sender/sender_x86_bpfel.go internal/bpf/reflector/reflector_x86_bpfel.go
.PHONY: bpf

internal/bpf/sender/sender_x86_bpfel.go internal/bpf/reflector/reflector_x86_bpfel.go &: internal/bpf/reflector.bpf.c internal/bpf/sender.bpf.c internal/bpf/stamp.bpf.h
	go generate ./internal/bpf

demo: binaries clean
	docker compose -f ./docker/demo/compose.yaml up -d -t0
	docker exec stamp_reflector tc qdisc add dev eth0 root netem delay 100ms 50ms 
	docker exec stamp_sender tc qdisc add dev eth0 root netem delay 50ms 25ms 
	docker exec -d stamp_reflector /home/bin/reflector eth0
	docker exec stamp_sender /home/bin/sender eth0 172.30.0.3 -i 500 -c 5 -s 862 -d 862
	docker compose -f ./docker/demo/compose.yaml down -t0
.PHONY: demo teststand releasedemo

releasedemo: binaries
	rm -f ./release/demo/sender ./release/demo/reflector ./release/demo/demo.zip
	cp ./cmd/bin/* ./release/demo
	docker compose -f ./release/demo/compose.yaml build
	docker save stampdemo > ./release/demo/image.gz
	zip -j ./release/demo/demo ./release/demo/*

clean:
	docker compose -f ./docker/demo/compose.yaml down -t0
.PHONY:clean
