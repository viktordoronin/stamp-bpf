ifndef VERBOSE
.SILENT:
endif

bindir=cmd/bin

sendersrc=cmd/sender/sender.go
senderskel=internal/bpf/sender/*.go

reflectorsrc=cmd/reflector/reflector.go
reflectorskel=internal/bpf/reflector/*.go

golibs=internal/userspace/*/*

bpfsrc=internal/bpf/*bpf.c internal/bpf/stamp.bpf.h

binaries: $(bindir)/sender $(bindir)/reflector
bpf: $(senderskel) $(reflectorskel)
.PHONY: binaries bpf

$(bindir)/sender: $(sendersrc) $(senderskel) $(golibs)
	CGO_ENABLED=0 go build -C ./cmd/sender -o ../bin/

$(bindir)/reflector: $(reflectorsrc) $(reflectorskel) $(golibs)
	CGO_ENABLED=0 go build -C ./cmd/reflector -o ../bin/

$(senderskel) $(reflectorskel) &: $(bpfsrc)
	go generate ./internal/bpf

test: binaries
	docker compose -f ./docker/testing/compose.yaml down -t0	
	docker compose -f ./docker/testing/compose.yaml up -d -t0
	docker exec stamp_reflector tc qdisc add dev eth0 root netem delay 100ms 20ms distribution normal
	docker exec stamp_sender tc qdisc add dev eth0 root netem delay 50ms 10ms distribution normal loss 20% 
	docker exec -d stamp_reflector /home/bin/reflector eth0 
	docker exec stamp_sender /home/bin/sender eth0 172.30.0.3 -i 0.5 -c 10 -s 1000 
	docker compose -f ./docker/testing/compose.yaml down -t0

demo: binaries
	rm -f  ./docker/demo/demo.zip
	cp ./$(bindir)/* ./docker/demo
	docker compose -f ./docker/demo/compose.yaml build
	docker save stampdemo > ./docker/demo/image.gz
	rm ./docker/demo/sender
	rm ./docker/demo/reflector
	zip -j ./docker/demo/demo ./docker/demo/*
	rm ./docker/demo/image.gz

release: binaries demo
	cp ./$(bindir)/* ./release
	cp ./docker/demo/demo.zip ./release

clean:
	docker compose -f ./docker/testing/compose.yaml down -t0
	rm -f ./cmd/bin/*
	rm -f ./release/*
	rm -f ./docker/demo/sender ./docker/demo/reflector ./docker/demo/image.gz ./docker/demo/demo.zip
.PHONY: clean demo test release

help:
	@ echo
	@ echo "make messages are suppressed by default - use VERBOSE=1 to see it\n"
	@ echo "make binaries - fully build sender/reflector. Location: ./cmd/bin/\n"
	@ echo "make bpf - compile the BPF programs and generate Go skeletons. Location: ./internal/bpf/\n"
	@ echo "make test - spin up a Docker test demo, useful for debugging and testing changes\n"
	@ echo "make clean - should be obvious unless you just bought Make\n"
