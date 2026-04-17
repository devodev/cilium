# Per-Gateway Envoy Deployment Gateway API Implementation

This package contains the enterprise Gateway API implementation that manages
dedicated per-`Gateway` infrastructure.

It is separate from the OSS Gateway API implementation and is selected through
a `GatewayClass` whose `spec.controllerName` matches `io.cilium/gateway-deployment-controller`

## Overview

For each managed `Gateway`, a separate control- (Envoy xDS server K8s Deployment)
and dataplane (Envoy K8s Deployment) reconciles.

```mermaid
flowchart TD
    subgraph Input["Input"]
        direction LR
        GC[GatewayClass<br/>controllerName=io.cilium/gateway-deployment-controller]
        GW[Gateway]
        R[Routes]
        GC ~~~ GW
        R ~~~ GW
    end

    subgraph Operator["Cilium Operator"]
        GCR[GatewayClassReconciler]
        PGR[GatewayReconciler]
    end

    subgraph Dataplane["Dataplane per Gateway"]
        CM[K8s ConfigMap<br/>Bootstrap config]
        SA[K8s ServiceAccount]
        DEP[K8s Deployment<br/>Envoy]
        SVC[K8s Service<br/>LoadBalancer]
        POD[Envoy Pods]
    end

    subgraph Controlplane["Controlplane per Gateway"]
        CPSA[K8s ServiceAccount]
        CPR[K8s Role]
        CPRB[K8s RoleBinding]
        CPDEP[K8s Deployment<br/>Control plane / xDS server]
        CPSVC[K8s Service<br/>xDS]
        CPPOD[Control plane / xDS server Pods]
    end

    GW -. references .-> GC
    R -. references .-> GW
    GC --> GCR
    GW --> PGR
    GC --> PGR

    PGR --> CM
    PGR --> SA
    PGR --> DEP
    PGR --> SVC

    DEP -->|creates| POD
    CM -->|configures| POD
    SA -->|provides identity| POD
    SVC -->|forwards traffic| POD

    PGR --> CPSA
    PGR --> CPR
    PGR --> CPRB
    PGR --> CPDEP
    PGR --> CPSVC

    CPRB -->|binds| CPR
    CPRB -->|authorizes| CPPOD
    CPSA -->|provides identity| CPPOD
    CPDEP -->|creates| CPPOD
    CPSVC -->|exposes xDS| CPPOD
    GW -.-> CPPOD
    POD -. fetches dynamic configuration .-> CPSVC
```

## Control Model

Reconcilers in this package:

- `GatewayClassReconciler`
  - validates ownership of matching `GatewayClass` objects
  - sets `GatewayClass` accepted status

- `GatewayReconciler`
  - watches `Gateway`
  - watches referenced `GatewayClass`
  - creates and updates the per-`Gateway` dataplane and controlplane resources
  - deletes managed resources when a `Gateway` no longer belongs to this controller
  - sets the custom `Gateway` status conditions `io.cilium/DataplaneReady` and `io.cilium/ControlplaneReady`
  - removes Cilium-owned custom `Gateway` status conditions on handoff
  - preserves unrelated `Gateway` status conditions owned by other controllers such as the xDS controlplane controller

- `gateway-api-controlplane`
  - watches the target `Gateway`
  - serves xDS for the per-`Gateway` Envoy dataplane
  - sets the standard `Gateway` status conditions `Accepted` and `Programmed`
  - relies on the operator-owned custom conditions to determine whether the `Gateway` still belongs to this implementation

### Dataplane

For a managed `Gateway`, the Gateway reconciler creates these dataplane resources:

- `ConfigMap`
  - contains the embedded Envoy bootstrap config

- `ServiceAccount`
  - provides a dedicated pod identity for the per-`Gateway` dataplane

- `Deployment`
  - runs two Envoy pod replicas by default
  - uses the dedicated dataplane `ServiceAccount`
  - starts `cilium-envoy` directly (no use of `cilium-envoy-starter`)
  - uses Envoy admin `/ready` for probes

- `Service`
  - type `LoadBalancer`
  - listener ports are derived from `Gateway.spec.listeners`
  - selects the Envoy pods for that `Gateway`

### Controlplane

For a managed `Gateway`, the Gateway reconciler creates these controlplane resources:

- `ServiceAccount`
  - provides a dedicated pod identity for the per-`Gateway` controlplane

- `Role`
  - grants namespaced read access to the managed `Gateway`
  - later also covers namespaced Route reads
  - cannot be restricted via `ResourceNames`, because the controller-runtime cache uses informer `list` and `watch`

- `RoleBinding`
  - binds the controlplane `ServiceAccount` to the namespaced `Role`

- `Deployment`
  - runs two `gateway-api-controlplane` pod replicas by default
  - passes the target `Gateway` namespace and name as flags
  - serves xDS, health, and metrics endpoints
  - does not use leader election today, because each replica maintains its own local xDS state and must be able to serve the dataplane through the shared `Service`
  - this means replicas may race on identical `Gateway` status updates, but avoids exposing follower replicas that cannot serve xDS

- `Service`
  - type `ClusterIP`
  - exposes the xDS gRPC endpoint to the dataplane Envoy pods

The controlplane stays namespaced-only. It does not read `Namespace` or
`GatewayClass` objects directly. Instead, it relies on the operator-owned custom
conditions `io.cilium/DataplaneReady` and `io.cilium/ControlplaneReady` to
determine whether the `Gateway` still belongs to this deployment-based
implementation. The operator removes its custom conditions during handoff,
which triggers one last controlplane reconcile via the `Gateway` update and
lets the controlplane clear its xDS snapshot without requiring cluster-scoped
RBAC.
