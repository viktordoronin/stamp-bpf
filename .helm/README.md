# stamp-bpf Helm Chart

## Description

This Helm chart deploys the STAMP (Simple Two-Way Active Measurement Protocol) implementation using eBPF technology. The chart deploys both sender and reflector components as DaemonSets to ensure network performance measurements across all nodes in your Kubernetes cluster.

STAMP is a network performance measurement protocol that provides metrics for individual directions (near-end and far-end). This implementation uses eBPF TC Classifier programs to timestamp packets directly inside the Linux networking stack, minimizing processing delay factors in measurements.

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- Linux kernel 6.6+ on worker nodes
- Privileged pod security policies enabled (due to eBPF requirements)
- Nodes with the required Linux capabilities:
  - `CAP_BPF`
  - `CAP_NET_ADMIN`
  - `CAP_NET_BIND_SERVICE` (for sender when using source port 862)

## Installation

### Add the repository

```bash
helm repo add stamp-bpf https://github.com/SPbNIX/stamp-bpf
```

### Install the chart

```bash
helm install my-release stamp-bpf/stamp-bpf
```

This command deploys stamp-bpf on the Kubernetes cluster with the default configuration.

### Uninstall the chart

```bash
helm uninstall my-release
```

This command removes all the Kubernetes components associated with the chart and deletes the release.

## Configuration

The following table lists the configurable parameters of the stamp-bpf chart and their default values.

### Global Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.image.repository` | Global image repository | `viktordoronin/stamp-bpf` |
| `global.image.tag` | Global image tag | `latest` |
| `global.image.pullPolicy` | Global image pull policy | `IfNotPresent` |
| `global.nodeSelector` | Node labels for pod assignment | `{}` |
| `global.tolerations` | Tolerations for pod assignment | `[]` |
| `global.affinity` | Affinity rules for pod assignment | `{}` |

### Sender Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `sender.enabled` | Enable/disable sender deployment | `true` |
| `sender.interface` | Interface to attach to for packet capture/transmission | `eth0` |
| `sender.reflectorIPs` | Reflector IP addresses (list to support multiple targets) | `[]` |
| `sender.sourcePort` | Source port for sending packets | `862` |
| `sender.destinationPort` | Destination port for sending packets | `862` |
| `sender.count` | Number of packets to send (0 for infinite) | `0` |
| `sender.interval` | Interval between packets (seconds) | `1.0` |
| `sender.timeout` | Timeout before packet considered lost (seconds) | `1` |
| `sender.debug` | Debug mode flag | `false` |
| `sender.histogram.enabled` | Enable histogram collection | `false` |
| `sender.histogram.bins` | Number of histogram bins | `28` |
| `sender.histogram.floor` | Histogram floor value (log10 scale) | `25` |
| `sender.histogram.ceiling` | Histogram ceiling value (log10 scale) | `75` |
| `sender.histogram.path` | Path to store histogram data | `/tmp/sender-hist` |
| `sender.enforceSync` | Enforce general clock synchronization | `false` |
| `sender.enforcePTP` | Enforce PTP clock synchronization | `false` |
| `sender.resources` | Resource limits and requests | `{}` |
| `sender.extraArgs` | Additional container arguments | `[]` |

### Reflector Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `reflector.enabled` | Enable/disable reflector deployment | `true` |
| `reflector.interface` | Interface to attach to for packet capture | `eth0` |
| `reflector.port` | Port to listen on for incoming packets | `862` |
| `reflector.debug` | Debug mode flag | `false` |
| `reflector.output` | Enable output for histogram and simultaneous sessions | `false` |
| `reflector.histogram.enabled` | Enable histogram collection | `false` |
| `reflector.histogram.bins` | Number of histogram bins | `28` |
| `reflector.histogram.floor` | Histogram floor value (log10 scale) | `25` |
| `reflector.histogram.ceiling` | Histogram ceiling value (log10 scale) | `75` |
| `reflector.histogram.path` | Path to store histogram data | `/tmp/reflector-hist` |
| `reflector.enforceSync` | Enforce general clock synchronization | `false` |
| `reflector.enforcePTP` | Enforce PTP clock synchronization | `false` |
| `reflector.resources` | Resource limits and requests | `{}` |
| `reflector.extraArgs` | Additional container arguments | `[]` |

### Monitoring Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.enabled` | Enable PodMonitor creation for metrics collection | `true` |
| `monitoring.interval` | Scrape interval for metrics collection | `15s` |
| `monitoring.relabelings` | Additional relabeling rules for PodMonitor | `[]` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.podSecurityContext` | Pod security context | `{}` |
| `security.containerSecurityContext.privileged` | Container security context with privileged mode enabled | `true` |

### Service Account Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Specifies whether a service account should be created | `true` |
| `serviceAccount.name` | The name of the service account to use | `""` |
| `serviceAccount.annotations` | Annotations to add to the service account | `{}` |

## Example Usage Scenarios

### Basic Deployment

To deploy the stamp-bpf with default settings:

```bash
helm install stamp-bpf-release stamp-bpf/stamp-bpf
```

### Deploy with Custom Reflector IPs

To deploy the sender component with specific reflector targets:

```bash
helm install stamp-bpf-release stamp-bpf/stamp-bpf \
  --set sender.reflectorIPs={"192.168.1.100","192.168.1.101"}
```

### Enable Histogram Collection

To enable histogram collection for both sender and reflector:

```bash
helm install stamp-bpf-release stamp-bpf/stamp-bpf \
  --set sender.histogram.enabled=true \
  --set reflector.histogram.enabled=true
```

### Deploy Only Reflector

To deploy only the reflector component:

```bash
helm install stamp-bpf-reflector stamp-bpf/stamp-bpf \
  --set sender.enabled=false
```

### Deploy Only Sender

To deploy only the sender component:

```bash
helm install stamp-bpf-sender stamp-bpf/stamp-bpf \
  --set reflector.enabled=false \
  --set sender.reflectorIPs={"192.168.1.100"}
```

## Monitoring and Metrics

The chart includes built-in support for monitoring with Prometheus through PodMonitor resources. When enabled, metrics are automatically collected from both sender and reflector components.

### Metrics Endpoints

- Sender metrics: `http://<pod-ip>:8080/metrics`
- Reflector metrics: `http://<pod-ip>:8080/metrics`

### Default Metrics

- Packet transmission statistics
- Latency measurements (near-end, far-end, roundtrip)
- Packet loss metrics
- Histogram data (when enabled)

### Customizing Monitoring

You can customize the monitoring configuration:

```bash
helm install stamp-bpf-release stamp-bpf/stamp-bpf \
  --set monitoring.interval=30s \
  --set monitoring.relabelings={...}
```

## Troubleshooting

### Common Issues

1. **BPF Program Load Failures**
   - Ensure worker nodes are running Linux kernel 6.6+
   - Check that required kernel flags are enabled
   - Verify node has sufficient privileges

2. **Network Connectivity Issues**
   - Check that reflector is running on the receiving side
   - Verify correct network device is being used
   - Ensure firewall rules allow traffic on specified ports

3. **Permission Errors**
   - Confirm that pods are running in privileged mode
   - Check that required Linux capabilities are granted
   - Verify namespace has appropriate pod security policies

### Debugging

To enable debug mode for components:

```bash
helm install stamp-bpf-release stamp-bpf/stamp-bpf \
  --set sender.debug=true \
  --set reflector.debug=true
```

Then check the pod logs:

```bash
kubectl logs -n <namespace> <sender-pod-name>
kubectl logs -n <namespace> <reflector-pod-name>
```