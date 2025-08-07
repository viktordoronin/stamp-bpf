# STAMP implementation for Go
This is a STAMP Protocol(RFC 8762) implementation using Go and eBPF. Implemented so far: stateless unauthenticated STAMP sessions(both sender and reflector). It's a rough but functional implementation so far.
# TODO
- Introduce config maps:
  - Sender: specify target IP(as opposed to hardcoded)
  - Specify ports
  - Userspace logs its own IP(for more robust For-me check)
- Userspace CLI options - inter-packet interval, packet count
- Stateful mode
- Advanced: combine sender and reflector into one binary(for ease of redistribution)
- More advanced: Authenticated mode using crypto KFuncs
# WONTDO
- Error estimate - I simply don't know how
- PTPv2 time format for the same reason
# Docker notes
- Start a container: `docker run -it --rm --privileged debian`
- Host IP: 172.18.0.1
- Mount debugfs:
  - inside container: `mount -t debugfs debugfs /sys/kernel/debug`
  - using daemon: `docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs` 
	- then mount it: `-v debugfs:/sys/kernel/debug:rw`
- Copy binary: `docker cp ./reflector.out nostalgic_gates:/home/reflector.out`
# Caps
- BPF portion requires CAP_BPF and CAP_NET_ADMIN; might require CAP_PERFMON in the future(check this if verifier yells at you) 
- CAP_NET_BIND_SERVICE is required for `sender` if we dial from **SOURCE** port 862
- do `sudo setcap 'cap_bpf=ep cap_net_admin=ep cap_net_bind_service=ep'` to do this in the shell; you can also set these caps in a Dockerfile
- Caps set on a binary persist between builds so you only have to do it once
