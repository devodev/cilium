# Gateway API Controlplane

This package contains the `gateway-api-controlplane` binary.

Its purpose is to run the per-Gateway xDS controlplane for the Gateway API
"Per-Gateway Envoy Deployment" mode:

It watches the target `Gateway`, translates that state into Envoy xDS resources
and serves xDS to the per-Gateway Envoy dataplane.
