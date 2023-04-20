#!/usr/bin/env python

# A service that mocks up various metadata providers. Used for testing,
# can also be used standalone as a development aid.
#
# To run standalone:
#
# run:     $ systemd-socket-activate -l 8000 python tools/test-cloud-meta-mock.py &
#          $ NM_CLOUD_SETUP_EC2_HOST=http://localhost:8000 \
#            NM_CLOUD_SETUP_LOG=trace \
#            NM_CLOUD_SETUP_EC2=yes src/nm-cloud-setup/nm-cloud-setup
# or just: $ python tools/test-cloud-meta-mock.py
#
# By default, the utility will server some resources for each known cloud
# providers, for convenience. The tests start this with "--empty" argument,
# which starts with no resources.

import os
import socket
from sys import argv

from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from socketserver import BaseServer


class MockCloudMDRequestHandler(BaseHTTPRequestHandler):
    """
    Respond to cloud metadata service requests.
    Currently implements a fairly minimal subset of AWS EC2 API.
    """

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        path = self.path.encode("ascii")
        if path in self.server._resources:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.server._resources[path])
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        path = self.path.encode("ascii")
        if path == b"/latest/api/token":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b"AQAAALH-k7i18JMkK-ORLZQfAa7nkNjQbKwpQPExNHqzk1oL_7eh-A=="
            )
        else:
            length = int(self.headers["content-length"])
            self.server._resources[path] = self.rfile.read(length)
            self.send_response(201)
            self.end_headers()

    def do_DELETE(self):
        path = self.path.encode("ascii")
        if path in self.server._resources:
            del self.server._resources[path]
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


class SocketHTTPServer(HTTPServer):
    """
    A HTTP server that accepts a socket (that has already been
    listen()-ed on). This is useful when the socket is passed
    fron the test runner.
    """

    def __init__(self, server_address, RequestHandlerClass, socket, resources):
        BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.socket = socket
        self.server_address = self.socket.getsockname()
        self._resources = resources


def default_resources():
    ec2_macs = b"/2018-09-24/meta-data/network/interfaces/macs/"

    mac1 = b"9e:c0:3e:92:24:2d"
    mac2 = b"53:e9:7e:52:8d:a8"

    ip1 = b"172.31.26.249"
    ip2 = b"172.31.176.249"

    return {
        b"/latest/meta-data/": b"ami-id\n",
        ec2_macs: mac2 + b"\n" + mac1,
        ec2_macs + mac2 + b"/subnet-ipv4-cidr-block": b"172.31.16.0/20",
        ec2_macs + mac2 + b"/local-ipv4s": ip1,
        ec2_macs + mac1 + b"/subnet-ipv4-cidr-block": b"172.31.166.0/20",
        ec2_macs + mac1 + b"/local-ipv4s": ip2,
    }


resources = None
try:
    if argv[1] == "--empty":
        resources = {}
except IndexError:
    pass
if resources is None:
    resources = default_resources()

# See sd_listen_fds(3)
fileno = os.getenv("LISTEN_FDS")
if fileno is not None:
    if fileno != "1":
        raise Exception("Bad LISTEN_FDS")
    s = socket.socket(fileno=3)
else:
    addr = ("localhost", 0)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(addr)

httpd = SocketHTTPServer(None, MockCloudMDRequestHandler, socket=s, resources=resources)

print("Listening on http://%s:%d" % (httpd.server_address[0], httpd.server_address[1]))
httpd.server_activate()

httpd.serve_forever()
httpd.server_close()
