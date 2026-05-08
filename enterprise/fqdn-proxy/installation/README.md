# cilium-dnsproxy

![Version: 1.20.0-dev](https://img.shields.io/badge/Version-1.20.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.20.0-dev](https://img.shields.io/badge/AppVersion-1.20.0--dev-informational?style=flat-square)

DNS Proxy for Isovalent Enterprise Grade eBPF-based Networking, Security, and Observability

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium-dnsproxy"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for cilium-dnsproxy. |
| annotations | object | `{}` | Annotations to be added to cilium-dnsproxy daemonset |
| debug | bool | `false` | Enable debug mode |
| dnsPolicy | string | `""` |  |
| extraArgs | list | `[]` |  |
| extraEnv | list | `[]` | Additional cilium-dnsproxy container environment variables. |
| extraVolumeMounts | list | `[]` | Additional cilium-dnsproxy volumeMounts. |
| extraVolumes | list | `[]` | Additional cilium-dnsproxy volumes. |
| image.imagePullPolicy | string | `"Always"` |  |
| image.override | string | `nil` |  |
| image.repository | string | `"quay.io/isovalent-dev/cilium-dnsproxy-ci"` |  |
| image.tag | string | `"latest"` |  |
| imagePullSecrets | list | `[]` | Image pull secrets for pulling container images |
| livenessProbe.enabled | bool | `true` | Enable liveness probe for dnsproxy container. |
| livenessProbe.failureThreshold | int | `10` | Failure threshold of dnsproxy container liveness probe. |
| livenessProbe.periodSeconds | int | `30` | Interval between checks of the liveness probe. |
| metrics.enabled | bool | `true` | Enable Prometheus metrics. |
| metrics.port | int | `9967` | Prometheus metrics port. |
| metrics.serviceMonitor.annotations | object | `{}` | Annotations to add to cilium-dnsproxy ServiceMonitor |
| metrics.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| metrics.serviceMonitor.labels | object | `{}` | Labels to add to cilium-dnsproxy ServiceMonitor |
| metrics.serviceMonitor.scrapeInterval | string | `"10s"` | Scrape interval. |
| nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for cilium-dnsproxy. Should match the Cilium agent. |
| offlineMode.enabled | bool | `false` | Enable support for offline writes to BPF This must also be enabled in the Cilium agent. |
| podAnnotations | object | `{}` | Annotations to be added to cilium-dnsproxy pods |
| podLabels | object | `{}` | Labels to be added to cilium-dnsproxy pods |
| podSecurityContext | object | `{}` | Security Context for cilium-dnsproxy pods. |
| pprof.address | string | `"localhost"` | Configure pprof listen address for cilium-dnsproxy |
| pprof.blockProfileRate | int | `0` | Enable goroutine blocking profiling for cilium-dnsproxy and set the rate of sampled events in nanoseconds (set to 1 to sample all events [warning: performance overhead]) |
| pprof.enabled | bool | `false` | Enable pprof for cilium-dnsproxy |
| pprof.mutexProfileFraction | int | `0` | Enable mutex contention profiling for cilium-dnsproxy and set the fraction of sampled events (set to 1 to sample all events) |
| pprof.port | int | `8920` | Configure pprof listen port for cilium-dnsproxy |
| priorityClassName | string | `"system-node-critical"` | The priority class to use for cilium-dnsproxy. |
| readinessProbe.enabled | bool | `true` | Enable readiness probe for dnsproxy container. |
| readinessProbe.failureThreshold | int | `3` | Failure threshold of dnsproxy container readiness probe. |
| readinessProbe.periodSeconds | int | `30` | Interval between checks of the readiness probe. |
| resources | object | `{}` | Cilium-dnsproxy resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| runPath | string | `"/var/run/cilium"` | Configure where Cilium runtime state should be stored. This must match the cilium agent. |
| securityContext | object | `{"allowPrivilegeEscalation":false}` | The pod security context, by default adds NET_ADMIN, NET_RAW and BPF (if needed). |
| serviceAccount.annotations | object | `{}` | Annotations for the service account |
| serviceAccount.automount | bool | `true` | Whether or not to mount the service account's token |
| serviceAccount.create | bool | `true` | Whether or not to create the cilium-dnsproxy service account |
| serviceAccount.name | string | `"cilium-dnsproxy"` | The name of the service account |
| startupProbe.enabled | bool | `true` | Enable startup probe for dnsproxy container. |
| startupProbe.failureThreshold | int | `60` | Failure threshold of dnsproxy container startup probe. Allow cilium-dnsproxy to take up to 120s to start up (60 attempts with 2s between attempts). |
| startupProbe.periodSeconds | int | `2` | Interval between checks of the startup probe |
| tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for proxy scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| updateStrategy | string | `nil` | cilium-dnsproxy update strategy |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.2.1](https://github.com/norwoodj/helm-docs/releases/v1.2.1)
