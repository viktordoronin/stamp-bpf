#!/bin/bash
function cleanup{
docker compose -f ./compose.yaml down -t0
}
trap cleanup EXIT
docker load -i image.gz
docker compose -f ./compose.yaml down -t0
docker compose -f ./compose.yaml up -d -t0;
docker exec stamp_reflector tc qdisc add dev eth0 root netem delay 100ms 20ms distribution normal loss 10%
docker exec stamp_sender tc qdisc add dev eth0 root netem delay 50ms 10ms distribution normal
docker exec -d stamp_reflector_demo /home/reflector eth0
docker exec stamp_sender_demo /home/sender eth0 172.31.0.3 -i 0.5 -c 50
