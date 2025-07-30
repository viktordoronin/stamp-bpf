# STAMP implementation for Go
This is a STAMP Protocol(RFC 8762) implementation using Go and eBPF. Implemented so far: stateless unauthenticated STAMP sessions(both sender and reflector). It's a rough but functional implementation so far.
# TODO
- Reorganize headers to minimize duplicated code
- Revisit timestamp generation(NTP conversion might still be erroneous)
- Introduce config maps:
  - Sender: specify target IP(as opposed to hardcoded)
  - Reflector: specify IP to listen to
  - Specify ports
  - Userspace logs its own IP(for more robust For-me check)
- Userspace CLI options - inter-packet interval, packet count
- Stateful mode
- Authenticated mode
- Advanced: combine sender and reflector into one binary(for ease of redistribution)
