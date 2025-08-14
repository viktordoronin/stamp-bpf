#!/bin/bash
tc qdisc add dev eth0 root netem delay 250ms
/home/reflector eth0
