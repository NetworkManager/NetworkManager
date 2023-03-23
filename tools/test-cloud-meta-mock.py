#!/usr/bin/env python

# run:     $ systemd-socket-activate -l 8000 python tools/test-cloud-meta-mock.py &
#          $ NM_CLOUD_SETUP_EC2_HOST=http://localhost:8000 \
#            NM_CLOUD_SETUP_LOG=trace \
#            NM_CLOUD_SETUP_EC2=yes src/nm-cloud-setup/nm-cloud-setup
# or just: $ python tools/test-cloud-meta-mock.py

import os
import socket

from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from socketserver import BaseServer


class MockCloudMDRequestHandler(BaseHTTPRequestHandler):
    """
    Respond to cloud metadata service requests.
    Currently implements a fairly minimal subset of AWS EC2 API.
    """

    _ec2_macs = "/2018-09-24/meta-data/network/interfaces/macs/"
    _meta_resources = {
        "/latest/meta-data/": b"ami-id\n",
        _ec2_macs: b"9e:c0:3e:92:24:2d\n53:e9:7e:52:8d:a8",
        _ec2_macs + "9e:c0:3e:92:24:2d/subnet-ipv4-cidr-block": b"172.31.16.0/20",
        _ec2_macs + "9e:c0:3e:92:24:2d/local-ipv4s": b"172.31.26.249",
        _ec2_macs + "53:e9:7e:52:8d:a8/subnet-ipv4-cidr-block": b"172.31.166.0/20",
        _ec2_macs + "53:e9:7e:52:8d:a8/local-ipv4s": b"172.31.176.249",
    }

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path in self._meta_resources:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self._meta_resources[self.path])
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        if self.path == "/latest/api/token":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b"AQAAALH-k7i18JMkK-ORLZQfAa7nkNjQbKwpQPExNHqzk1oL_7eh-A=="
            )
        else:
            self.send_response(404)
            self.end_headers()


class SocketHTTPServer(HTTPServer):
    """
    A HTTP server that accepts a socket (that has already been
    listen()-ed on). This is useful when the socket is passed
    fron the test runner.
    """

    def __init__(self, server_address, RequestHandlerClass, socket):
        BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.socket = socket
        self.server_address = self.socket.getsockname()


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


httpd = SocketHTTPServer(None, MockCloudMDRequestHandler, socket=s)

print("Listening on http://%s:%d" % (httpd.server_address[0], httpd.server_address[1]))
httpd.server_activate()

httpd.serve_forever()
httpd.server_close()
