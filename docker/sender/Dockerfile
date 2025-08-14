# syntax=docker/dockerfile:1
FROM debian:latest
COPY ./docker/sender/entrypoint.sh ./cmd/bin/sender /home/
RUN <<EOL
    apt -y update
    apt -y install iproute2 iputils-ping
EOL
ENTRYPOINT /home/entrypoint.sh
