#!/bin/bash
docker load -i image.gz;
docker compose -f ./compose.yaml down -t0;
docker compose -f ./compose.yaml up -d -t0;
docker exec stamp_reflector_demo tc qdisc add dev eth0 root netem delay 100ms;
docker exec stamp_sender_demo tc qdisc add dev eth0 root netem delay 50ms;
docker exec -d stamp_reflector_demo /home/reflector eth0;
docker exec stamp_sender_demo /home/sender eth0 172.31.0.3 -c 10;
docker compose -f ./compose.yaml down -t0;
