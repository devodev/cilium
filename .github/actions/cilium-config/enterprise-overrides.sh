#!/usr/bin/env bash
# Enterprise only config additions, sourced from actions/cilium-config/action.yml

if [ "${ENTERPRISE_VRF:-false}" == "true" ]; then
  CONFIG="${CONFIG} --helm-set=enterprise.vrf.enabled=true"
fi
