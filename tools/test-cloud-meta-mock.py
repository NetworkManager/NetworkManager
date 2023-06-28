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
import sys

from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from socketserver import BaseServer


PROVIDERS = [
    "aliyun",
    "azure",
    "ec2",
    "gcp",
]


def _s_to_bool(s):
    s0 = s
    if isinstance(s, bytes):
        s = s.encode("utf-8", errors="replace")
    if isinstance(s, str):
        s = s.lower()
        if s in ["yes", "y", "true", "1"]:
            return True
        if s in ["no", "n", "false", "0"]:
            return False
    if isinstance(s, int):
        if s in [0, 1]:
            return s == 1
    raise ValueError('Not a boolean value ("%s")' % (s0,))


DEBUG = _s_to_bool(os.environ.get("NM_TEST_CLOUD_SETUP_MOCK_DEBUG", "0"))


def dbg(msg):
    if DEBUG:
        print("DBG: %s" % (msg,))


class MockCloudMDRequestHandler(BaseHTTPRequestHandler):
    """
    Respond to cloud metadata service requests.
    Currently implements a fairly minimal subset of AWS EC2 API.
    """

    def log_message(self, format, *args):
        pass

    def _response_and_end(self, code, write=None):
        self.send_response(code)
        self.end_headers()
        if write is None:
            dbg("response %s" % (code,))
        else:
            if isinstance(write, str):
                write = write.encode("utf-8")
            dbg("response %s, %s" % (code, write))
            self.wfile.write(write)

    def _read(self):
        length = int(self.headers["content-length"])
        v = self.rfile.read(length)
        dbg('receive "%s"' % (v,))
        return v

    def do_GET(self):
        path = self.path.encode("ascii")
        dbg("GET %s" % (path,))
        r = None
        if path in self.server._resources:
            r = self.server._resources[path]
        elif self.server.config_get_allow_default():
            for p in self.server.config_get_providers():
                if path in DEFAULT_RESOURCES[p]:
                    r = DEFAULT_RESOURCES[p][path]
                    break
        if r is None:
            self._response_and_end(404)
            return
        self._response_and_end(200, write=r)

    def do_PUT(self):
        path = self.path.encode("ascii")
        dbg("PUT %s" % (path,))
        if path.startswith(b"/.nmtest/"):
            conf_name = path[len(b"/.nmtest/") :]
            v = self._read()

            self.server._config[conf_name] = v

            assert self.server.config_get_providers() is not None
            assert self.server.config_get_allow_default() is not None

            self._response_and_end(201)
        elif path == b"/latest/api/token":
            if "ec2" not in self.server.config_get_providers():
                self._response_and_end(404)
            else:
                self._response_and_end(
                    200,
                    write="AQAAALH-k7i18JMkK-ORLZQfAa7nkNjQbKwpQPExNHqzk1oL_7eh-A==",
                )
        else:
            self.server._resources[path] = self._read()
            self._response_and_end(201)

    def do_DELETE(self):
        path = self.path.encode("ascii")
        dbg("DELETE %s" % (path,))
        if path in self.server._resources:
            del self.server._resources[path]
            self._response_and_end(204)
        else:
            self._response_and_end(404)


class SocketHTTPServer(HTTPServer):
    """
    A HTTP server that accepts a socket (that has already been
    listen()-ed on). This is useful when the socket is passed
    fron the test runner.
    """

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        socket,
        resources=None,
        allow_default=True,
    ):
        BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.socket = socket
        self.server_address = self.socket.getsockname()
        self._resources = resources or {}
        self._config = {
            "allow-default": "yes" if allow_default else "no",
        }

    def config_get_providers(self):
        conf = self._config.get(b"providers", None)
        if not conf:
            return PROVIDERS
        parsed = [s.lower() for s in conf.decode("utf-8", errors="replace").split(" ")]
        assert all(p in PROVIDERS for p in parsed)
        return parsed

    def config_get_allow_default(self):
        return _s_to_bool(self._config.get(b"allow-default", "yes"))


def create_default_resources_for_provider(provider):

    mac1 = b"cc:00:00:00:00:01"
    mac2 = b"cc:00:00:00:00:02"

    ip1 = b"172.31.26.249"
    ip2 = b"172.31.176.249"

    if provider == "aliyun":
        aliyun_meta = b"/2016-01-01/meta-data/"
        aliyun_macs = aliyun_meta + b"network/interfaces/macs/"
        return {
            aliyun_meta: b"ami-id\n",
            aliyun_macs: mac2 + b"\n" + mac1,
            aliyun_macs + mac2 + b"/vpc-cidr-block": b"172.31.16.0/20",
            aliyun_macs + mac2 + b"/private-ipv4s": ip1,
            aliyun_macs + mac2 + b"/primary-ip-address": ip1,
            aliyun_macs + mac2 + b"/netmask": b"255.255.255.0",
            aliyun_macs + mac2 + b"/gateway": b"172.31.26.2",
            aliyun_macs + mac1 + b"/vpc-cidr-block": b"172.31.166.0/20",
            aliyun_macs + mac1 + b"/private-ipv4s": ip2,
            aliyun_macs + mac1 + b"/primary-ip-address": ip2,
            aliyun_macs + mac1 + b"/netmask": b"255.255.255.0",
            aliyun_macs + mac1 + b"/gateway": b"172.31.176.2",
        }

    if provider == "azure":
        azure_meta = b"/metadata/instance"
        azure_iface = azure_meta + b"/network/interface/"
        azure_query = b"?format=text&api-version=2017-04-02"
        return {
            azure_meta + azure_query: b"",
            azure_iface + azure_query: b"0\n1\n",
            azure_iface + b"0/macAddress" + azure_query: mac1,
            azure_iface + b"1/macAddress" + azure_query: mac2,
            azure_iface + b"0/ipv4/ipAddress/" + azure_query: b"0\n",
            azure_iface + b"1/ipv4/ipAddress/" + azure_query: b"0\n",
            azure_iface + b"0/ipv4/ipAddress/0/privateIpAddress" + azure_query: ip1,
            azure_iface + b"1/ipv4/ipAddress/0/privateIpAddress" + azure_query: ip2,
            azure_iface + b"0/ipv4/subnet/0/address/" + azure_query: b"172.31.16.0",
            azure_iface + b"1/ipv4/subnet/0/address/" + azure_query: b"172.31.166.0",
            azure_iface + b"0/ipv4/subnet/0/prefix/" + azure_query: b"20",
            azure_iface + b"1/ipv4/subnet/0/prefix/" + azure_query: b"20",
        }

    if provider == "ec2":
        ec2_macs = b"/2018-09-24/meta-data/network/interfaces/macs/"
        return (
            {
                b"/latest/meta-data/": b"ami-id\n",
                ec2_macs: mac2 + b"\n" + mac1,
                ec2_macs + mac2 + b"/subnet-ipv4-cidr-block": b"172.31.16.0/20",
                ec2_macs + mac2 + b"/local-ipv4s": ip1,
                ec2_macs + mac1 + b"/subnet-ipv4-cidr-block": b"172.31.166.0/20",
                ec2_macs + mac1 + b"/local-ipv4s": ip2,
            },
        )

    if provider == "gcp":
        gcp_meta = b"/computeMetadata/v1/instance/"
        gcp_iface = gcp_meta + b"network-interfaces/"
        return {
            gcp_meta + b"id": b"",
            gcp_iface: b"0\n1\n",
            gcp_iface + b"0/mac": mac1,
            gcp_iface + b"1/mac": mac2,
            gcp_iface + b"0/forwarded-ips/": b"0\n",
            gcp_iface + b"0/forwarded-ips/0": ip1,
            gcp_iface + b"1/forwarded-ips/": b"0\n",
            gcp_iface + b"1/forwarded-ips/0": ip2,
        }

    raise ValueError("invalid provider %s" % (provider,))


def create_default_resources():

    return {p: create_default_resources_for_provider(p) for p in PROVIDERS}


DEFAULT_RESOURCES = create_default_resources()


allow_default = True
try:
    if sys.argv[1] == "--empty":
        allow_default = False
except IndexError:
    pass

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

httpd = SocketHTTPServer(
    None,
    MockCloudMDRequestHandler,
    socket=s,
    allow_default=allow_default,
)

print("Listening on http://%s:%d" % (httpd.server_address[0], httpd.server_address[1]))
httpd.server_activate()

httpd.serve_forever()
httpd.server_close()
