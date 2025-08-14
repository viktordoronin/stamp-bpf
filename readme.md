# STAMP implementation for Go
This is a STAMP Protocol(RFC 8762) implementation using Go and eBPF. Implemented so far: stateless unauthenticated STAMP sessions(both sender and reflector). It's a rough but functional implementation so far.

# Demo instructions
Once you unzip the archive, you can run `demo.sh` for a quick and easy Docker-based local demo. You should see ~50ms near-end delay and ~100ms far-end delay.

You're also provided binaries for testing over live network. They're statically linked and should require no dependencies, but they require 6.6 Kernel and either root or [linux capabilities](#caps).

`reflector` takes interface name, attaches to that interface and listens(not really since it's a BPF filter) on port 862:
```
sudo reflector eth0
```
`reflector` can handle several sessions at once and doesn't keep track of individual sessions (stateful mode) at this time. 
**IMPORTANT**: `reflector` needs to remain running in order for the program to function; use `&` if you'll need to use the same shell! 

`sender` takes interface name and IP, attaches the BPF components to provided interface and starts sending packets to that IP to and from port 862:
```
sudo sender eth0 111.222.33.44
```
There are `ping`-like options for packet count(`-c`) and send interval(`-i`) (**WARNING: might be unstable**). You'll have to quit this program with `Ctrl+C` when it's done. It only does one STAMP session at a time. 

# TODO (in this order(more or less))
- Introduce config maps:
  - Sender: specify target IP(as opposed to hardcoded)
  - Specify ports
  - Userspace logs its own IP(for more robust For-me check)
- (reflector) Stateful mode
- Advanced: combine sender and reflector into one binary(for ease of redistribution)
- QoL features: 
  - Userspace CLI options - inter-packet interval, packet count
  - pin mode to make the BPF programs work as a network daemon
  - cron scheduling
  - TBA
- More advanced: Authenticated mode using crypto KFuncs

# WONTDO (subject to change)
- Error estimate - I simply don't know how
- PTPv2 time format for the same reason

# Notes, ideas, musings

## Docker
- Start a container: `docker run -it --rm --privileged debian`
- Host IP: 172.18.0.1
- Mount debugfs:
  - inside container: `mount -t debugfs debugfs /sys/kernel/debug`
  - using daemon: `docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs` 
	- then mount it: `-v debugfs:/sys/kernel/debug:rw`
- Copy binary: `docker cp ./reflector.out _CONT_NAME_:/home/reflector.out`

## Caps
- BPF portion requires CAP_BPF and CAP_NET_ADMIN; might require CAP_PERFMON in the future(check this if verifier yells at you) 
- CAP_NET_BIND_SERVICE is required for `sender` if we dial from **SOURCE** port 862
- do `sudo setcap 'cap_bpf=ep cap_net_admin=ep cap_net_bind_service=ep'` to do this in the shell; you can also set these caps in Docker Compose if you use that

## bpf2go notes
- you can have several `go:generate` directives at once
- skeletons inherit package name from the `.go` file, so something like `package stamp` seems appropriate
- capitalizing the stem exports all objects of the skeleton, allowing to reference it from another package
- by having separate `.c` files, each generating its own scaffolding, we can work around the inability to load programs individually by bundling them
- this allows us to have BPF stuff in one package and Go stuff in another pakage reasonably seamlessly
- we can also target a `.c` in another directory; the skeleton will still be generated in the directory where the `go:generate` directive lives. I won't be using it here but it's useful if you're really anal about separating language files

## Authenticated mode notes
- It is possible using KFuncs
- [`bpf_crypto_encrypt()`](https://docs.ebpf.io/linux/kfuncs/bpf_crypto_encrypt/)/[`_decrypt()`](https://docs.ebpf.io/linux/kfuncs/bpf_crypto_decrypt/) are available for TC programs
- Use of these functions requires us to use [`bpf_crypto_ctx_create`](https://docs.ebpf.io/linux/kfuncs/bpf_crypto_ctx_create/), which is only available for program type [BPF_PROG_TYPE_SYSCALL](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SYSCALL/). So this will necessitate a separate program which will be loaded and executed before sender/reflector components.
