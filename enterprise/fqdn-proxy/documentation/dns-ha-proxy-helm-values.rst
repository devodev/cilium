..
  AUTO-GENERATED. Please DO NOT edit manually.


.. list-table::
   :header-rows: 1

   * - :spelling:ignore:`Key`
     - Description
     - Type
     - Default
   * - :spelling:ignore:`affinity`
     - Affinity for cilium-dnsproxy.
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium-dnsproxy"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - :spelling:ignore:`annotations`
     - Annotations to be added to cilium-dnsproxy daemonset
     - object
     - ``{}``
   * - :spelling:ignore:`debug`
     - Enable debug mode
     - bool
     - ``false``
   * - :spelling:ignore:`dnsPolicy`
     - 
     - string
     - ``""``
   * - :spelling:ignore:`extraArgs`
     - Additional cilium-dnsproxy container arguments.
     - list
     - ``[]``
   * - :spelling:ignore:`extraEnv`
     - Additional cilium-dnsproxy container environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`extraVolumeMounts`
     - Additional cilium-dnsproxy volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`extraVolumes`
     - Additional cilium-dnsproxy volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`image.imagePullPolicy`
     - 
     - string
     - ``"Always"``
   * - :spelling:ignore:`image.override`
     - 
     - string
     - ``nil``
   * - :spelling:ignore:`image.repository`
     - 
     - string
     - ``"quay.io/isovalent-dev/cilium-dnsproxy-ci"``
   * - :spelling:ignore:`image.tag`
     - 
     - string
     - ``"latest"``
   * - :spelling:ignore:`imagePullSecrets`
     - Image pull secrets for pulling container images
     - list
     - ``[]``
   * - :spelling:ignore:`livenessProbe.enabled`
     - Enable liveness probe for dnsproxy container.
     - bool
     - ``true``
   * - :spelling:ignore:`livenessProbe.failureThreshold`
     - Failure threshold of dnsproxy container liveness probe.
     - int
     - ``10``
   * - :spelling:ignore:`livenessProbe.periodSeconds`
     - Interval between checks of the liveness probe.
     - int
     - ``30``
   * - :spelling:ignore:`metrics.enabled`
     - Enable Prometheus metrics.
     - bool
     - ``true``
   * - :spelling:ignore:`metrics.port`
     - Prometheus metrics port.
     - int
     - ``9967``
   * - :spelling:ignore:`metrics.serviceMonitor.annotations`
     - Annotations to add to cilium-dnsproxy ServiceMonitor
     - object
     - ``{}``
   * - :spelling:ignore:`metrics.serviceMonitor.enabled`
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - :spelling:ignore:`metrics.serviceMonitor.labels`
     - Labels to add to cilium-dnsproxy ServiceMonitor
     - object
     - ``{}``
   * - :spelling:ignore:`metrics.serviceMonitor.scrapeInterval`
     - Scrape interval.
     - string
     - ``"10s"``
   * - :spelling:ignore:`nodeSelector`
     - Node selector for cilium-dnsproxy. Should match the Cilium agent.
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`offlineMode.enabled`
     - Enable support for offline writes to BPF This must also be enabled in the Cilium agent.
     - bool
     - ``false``
   * - :spelling:ignore:`podAnnotations`
     - Annotations to be added to cilium-dnsproxy pods
     - object
     - ``{}``
   * - :spelling:ignore:`podLabels`
     - Labels to be added to cilium-dnsproxy pods
     - object
     - ``{}``
   * - :spelling:ignore:`podSecurityContext`
     - Security Context for cilium-dnsproxy pods.
     - object
     - ``{}``
   * - :spelling:ignore:`pprof.address`
     - Configure pprof listen address for cilium-dnsproxy
     - string
     - ``"localhost"``
   * - :spelling:ignore:`pprof.blockProfileRate`
     - Enable goroutine blocking profiling for cilium-dnsproxy and set the rate of sampled events in nanoseconds (set to 1 to sample all events [warning: performance overhead])
     - int
     - ``0``
   * - :spelling:ignore:`pprof.enabled`
     - Enable pprof for cilium-dnsproxy
     - bool
     - ``false``
   * - :spelling:ignore:`pprof.mutexProfileFraction`
     - Enable mutex contention profiling for cilium-dnsproxy and set the fraction of sampled events (set to 1 to sample all events)
     - int
     - ``0``
   * - :spelling:ignore:`pprof.port`
     - Configure pprof listen port for cilium-dnsproxy
     - int
     - ``8920``
   * - :spelling:ignore:`priorityClassName`
     - The priority class to use for cilium-dnsproxy.
     - string
     - ``"system-node-critical"``
   * - :spelling:ignore:`readinessProbe.enabled`
     - Enable readiness probe for dnsproxy container.
     - bool
     - ``true``
   * - :spelling:ignore:`readinessProbe.failureThreshold`
     - Failure threshold of dnsproxy container readiness probe.
     - int
     - ``3``
   * - :spelling:ignore:`readinessProbe.periodSeconds`
     - Interval between checks of the readiness probe.
     - int
     - ``30``
   * - :spelling:ignore:`resources`
     - Cilium-dnsproxy resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - :spelling:ignore:`runPath`
     - Configure where Cilium runtime state should be stored. This must match the cilium agent.
     - string
     - ``"/var/run/cilium"``
   * - :spelling:ignore:`securityContext`
     - The pod security context, by default adds NET_ADMIN, NET_RAW and BPF (if needed).
     - object
     - ``{"allowPrivilegeEscalation":false}``
   * - :spelling:ignore:`serviceAccount.annotations`
     - Annotations for the service account
     - object
     - ``{}``
   * - :spelling:ignore:`serviceAccount.automount`
     - Whether or not to mount the service account's token
     - bool
     - ``true``
   * - :spelling:ignore:`serviceAccount.create`
     - Whether or not to create the cilium-dnsproxy service account
     - bool
     - ``true``
   * - :spelling:ignore:`serviceAccount.name`
     - The name of the service account
     - string
     - ``"cilium-dnsproxy"``
   * - :spelling:ignore:`startupProbe.enabled`
     - Enable startup probe for dnsproxy container.
     - bool
     - ``true``
   * - :spelling:ignore:`startupProbe.failureThreshold`
     - Failure threshold of dnsproxy container startup probe. Allow cilium-dnsproxy to take up to 120s to start up (60 attempts with 2s between attempts).
     - int
     - ``60``
   * - :spelling:ignore:`startupProbe.periodSeconds`
     - Interval between checks of the startup probe
     - int
     - ``2``
   * - :spelling:ignore:`tolerations`
     - Node tolerations for proxy scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[{"operator":"Exists"}]``
   * - :spelling:ignore:`updateStrategy`
     - cilium-dnsproxy update strategy
     - string
     - ``nil``
