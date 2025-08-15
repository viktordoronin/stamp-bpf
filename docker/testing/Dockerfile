# syntax=docker/dockerfile:1
FROM ubuntu:latest
RUN <<EOL
    apt -y update
    apt -y install iproute2 iputils-ping
EOL
ENTRYPOINT tail -F /dev/null
