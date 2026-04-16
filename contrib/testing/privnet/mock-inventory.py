# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

port = os.getenv("CILIUM_PRIVNET_PORT", default="8000")
dns_server = os.getenv("CILIUM_PRIVNET_DNS_SERVER", default="8.8.8.8")

network_tmpl = """
{{
  "id": "{id}",
  "path": "/v-bridge/network/{name}",
  "name": "{name}",
  "selfLink": "/providers/mock/networks/{id}",
  "variant": "Standard"
}}
"""

vm_tmpl = """
{{
  "id": "{id}",
  "path": "/v-bridge/vm/{id}",
  "name": "{name}",
  "selfLink": "/providers/mock/vms/{id}",
  "revisionValidated": 535,
  "networks": [
    {{
      "kind": "Network",
      "id": "{netID}"
    }}
  ],
  "cpuCount": 2,
  "memoryMB": 1024,
  "guestName": "Ubuntu Linux (64-bit)",
  "guestId": "ubuntu64Guest",
  "ipAddress": "{ip4}",
  "devices": [
    {{
      "kind": "VirtualVmxnet3"
    }}
  ],
  "nics": [
    {{
      "network": {{
        "kind": "Network",
        "id": "{netID}"
      }},
      "mac": "{mac}"
    }}
  ],
  "guestNetworks": [
    {{
      "device": "0",
      "mac": "{mac}",
      "ip": "{ip4}",
      "prefix": 24
    }},
    {{
      "device": "0",
      "mac": "{mac}",
      "ip": "{ip6}",
      "prefix": 128
    }},
    {{
      "device": "0",
      "mac": "{mac}",
      "ip": "fe80::250:56ff:fe8c:af6f",
      "prefix": 64
    }}
  ],
  "guestIpStacks": [
    {{
      "device": "0",
      "dns": ["{dns}"]
    }}
  ],
  "secureBoot": false
}}
"""

data = {
    "network-01": {
        "tmpl": network_tmpl,
        "name": "network-a",
    },
    "network-02": {
        "tmpl": network_tmpl,
        "name": "network-b",
    },
    "network-03": {
        "tmpl": network_tmpl,
        "name": "network-c",
    },
    "vm-A0": {
        "tmpl": vm_tmpl,
        "name": "test-webhook",
        "netID": "network-01",
        "ip4": "192.168.250.16",
        "ip6": "fd10:0:250::80",
        "mac": "00:50:56:8c:af:6f",
        "dns": dns_server,
    },
    "vm-A1": {
        "tmpl": vm_tmpl,
        "name": "client-network-a",
        "netID": "network-01",
        "ip4": "192.168.250.10",
        "ip6": "fd10:0:250::10",
        "mac": "f2:54:1c:1f:84:94",
        "dns": dns_server,
    },
    "vm-A2": {
        "tmpl": vm_tmpl,
        "name": "echo-same-node-network-a",
        "netID": "network-01",
        "ip4": "192.168.250.20",
        "ip6": "fd10:0:250::20",
        "mac": "de:a9:fd:7d:af:bf",
        "dns": dns_server,
    },
    "vm-A3": {
        "tmpl": vm_tmpl,
        "name": "echo-other-node-network-a",
        "netID": "network-01",
        "ip4": "192.168.250.21",
        "ip6": "fd10:0:250::21",
        "mac": "be:68:f6:fc:6a:4a",
        "dns": dns_server,
    },
    "vm-B1": {
        "tmpl": vm_tmpl,
        "name": "client-network-b",
        "netID": "network-02",
        "ip4": "192.168.251.10",
        "ip6": "fd10:0:251::10",
        "mac": "42:f9:eb:33:4d:54",
        "dns": dns_server,
    },
}


class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    base = "/providers/"

    def do_GET(self):
        path_segments = self.path.split('/')
        if (not self.path.startswith(self.base)) or (len(path_segments) < 5):
            self.send_response(404, "Not found")
            self.end_headers()
        elif path_segments[4] == "vms":
            self.do()
        elif path_segments[4] == "networks":
            self.do()
        else:
            self.send_response(404, "Not found")
            self.end_headers()

    def do(self):
        id = self.path.split('/')[-1]

        try:
            info = data[id]
            info["id"] = id

            self.send_response(200)
            self.end_headers()
            self.wfile.write(info["tmpl"].format(**info).encode())

        except KeyError as e:
            self.send_response(404, "Not found")
            print(str(e))
            self.end_headers()


HTTPServerV6(("::", int(port)), Handler).serve_forever()
