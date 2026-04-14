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
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

port = os.getenv("CILIUM_PRIVNET_PORT", default="8000")
dns_server = os.getenv("CILIUM_PRIVNET_DNS_SERVER", default="8.8.8.8")


def render_network(id, info):
    return {
        "id": id,
        "path": f"/v-bridge/network/{info['name']}",
        "name": info["name"],
        "selfLink": f"/providers/mock/networks/{id}",
        "variant": "Standard",
    }


def render_vm(id, info):
    ifaces = info["interfaces"]
    dns = info["dns"]

    guest_networks = []
    for idx, iface in enumerate(ifaces):
        guest_networks.extend([
            {
                "device": str(idx),
                "mac": iface["mac"],
                "ip": iface["ip4"],
                "prefix": 24,
            },
            {
                "device": str(idx),
                "mac": iface["mac"],
                "ip": iface["ip6"],
                "prefix": 128,
            },
            {
                "device": str(idx),
                "mac": iface["mac"],
                "ip": "fe80::250:56ff:fe8c:af6f",
                "prefix": 64,
            },
        ])

    return {
        "id": id,
        "path": f"/v-bridge/vm/{id}",
        "name": info["name"],
        "selfLink": f"/providers/mock/vms/{id}",
        "revisionValidated": 535,
        "networks": [
            {"kind": "Network", "id": iface["netID"]} for iface in ifaces
        ],
        "cpuCount": 2,
        "memoryMB": 1024,
        "guestName": "Ubuntu Linux (64-bit)",
        "guestId": "ubuntu64Guest",
        "ipAddress": ifaces[0]["ip4"],
        "devices": [{"kind": "VirtualVmxnet3"} for iface in ifaces],
        "nics": [
            {
                "network": {"kind": "Network", "id": iface["netID"]},
                "mac": iface["mac"],
            }
            for iface in ifaces
        ],
        "guestNetworks": guest_networks,
        "guestIpStacks": [
            {"device": str(idx), "dns": [dns]} for idx, _ in enumerate(ifaces)
        ],
        "secureBoot": False,
    }


data = {
    "network-01": {
        "render": render_network,
        "name": "network-a",
    },
    "network-02": {
        "render": render_network,
        "name": "network-b",
    },
    "network-03": {
        "render": render_network,
        "name": "network-c",
    },
    "vm-A0": {
        "render": render_vm,
        "name": "test-webhook",
        "interfaces": [
            {
                "netID": "network-01",
                "ip4": "192.168.250.16",
                "ip6": "fd10:0:250::80",
                "mac": "00:50:56:8c:af:6f",
            }
        ],
        "dns": dns_server,
    },
    "vm-A1": {
        "render": render_vm,
        "name": "client-network-a",
        "interfaces": [
            {
                "netID": "network-01",
                "ip4": "192.168.250.10",
                "ip6": "fd10:0:250::10",
                "mac": "f2:54:1c:1f:84:94",
            }
        ],
        "dns": dns_server,
    },
    "vm-A2": {
        "render": render_vm,
        "name": "echo-same-node-network-a",
        "interfaces": [
            {
                "netID": "network-01",
                "ip4": "192.168.250.20",
                "ip6": "fd10:0:250::20",
                "mac": "de:a9:fd:7d:af:bf",
            }
        ],
        "dns": dns_server,
    },
    "vm-A3": {
        "render": render_vm,
        "name": "echo-other-node-network-a",
        "interfaces": [
            {
                "netID": "network-01",
                "ip4": "192.168.250.21",
                "ip6": "fd10:0:250::21",
                "mac": "be:68:f6:fc:6a:4a",
            }
        ],
        "dns": dns_server,
    },
    "vm-B1": {
        "render": render_vm,
        "name": "client-network-b",
        "interfaces": [
            {
                "netID": "network-02",
                "ip4": "192.168.251.10",
                "ip6": "fd10:0:251::10",
                "mac": "42:f9:eb:33:4d:54",
            }
        ],
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

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(info["render"](id, info)).encode())

        except KeyError as e:
            self.send_response(404, "Not found")
            print(str(e))
            self.end_headers()


HTTPServerV6(("::", int(port)), Handler).serve_forever()
