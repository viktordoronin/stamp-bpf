#!/bin/bash
# TODO: look into setting these from the Go program
tc qdisc add dev eth0 root netem delay 150ms
tail -F /dev/null
