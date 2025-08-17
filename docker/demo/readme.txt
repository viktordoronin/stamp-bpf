Requirements:
- Docker
- 6.6 kernel
If this fails to run for any reason please let me know: https://github.com/viktordoronin/stamp-bpf

The Docker network uses 172.31.0.0/16 subnet so make sure you're not already using that.
To start, simply run demo.sh - you should see ~50ms near-end delay and ~100ms far-end delay with some variation(~10-15% jitter) and around 10% packet loss. 
