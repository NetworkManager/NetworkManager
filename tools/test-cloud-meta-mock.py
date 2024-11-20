#!/usr/bin/env python3

# A service that mocks up various metadata providers. Used for testing,
# can also be used standalone as a development aid.
#
# To run standalone:
#
# run:     $ python3 tools/test-cloud-meta-mock.py 8000 &
#          $ NM_CLOUD_SETUP_EC2_HOST=http://localhost:8000 \
#            NM_CLOUD_SETUP_LOG=trace \
#            NM_CLOUD_SETUP_EC2=yes \
#            NM_CLOUD_SETUP_MAP_INTERFACES="veth0=cc:00:00:00:00:01;veth1=cc:00:00:00:00:02" \
#            build/src/nm-cloud-setup/nm-cloud-setup
# or just: $ python3 tools/test-cloud-meta-mock.py
#
# By default, the utility will server some resources for each known cloud
# providers, for convenience. The tests start this with "--empty" argument,
# which starts with no resources.
#
# To add or edit resources use HTTP PUT instead of GET. This allow to create the
# resources that the test needs during its preparation step.
# - If the resource is a resource leaf, plain strings are accepted.
# - If it's a compound resource like the entire definition of a VNIC or even the whole
#   list of all VNICs definition, the content must be JSON with the same schema that the
#   real server has.
# - If the path doesn't exist all the parents of the path are automatically created.
# - For lists it is not valid to try PUTing an element with index > len(list), but it
#   is valid with == len(list) in which case it's added to the end of the list.
#
# To delete resources use HTTP DELETE.

import os
import socket
import sys
import time
import json

try:
    from http.server import ThreadingHTTPServer
except ImportError:
    print("No threading supported, azure race tests will never fail.")
    from http.server import HTTPServer as ThreadingHTTPServer
from http.server import BaseHTTPRequestHandler
from socketserver import BaseServer


PROVIDERS = {
    "aliyun": "text",
    "azure": "text",
    "ec2": "text",
    "gcp": "text",
    "oci": "json",
}

PATHS_TO_PROVIDERS_MAP = {
    "2016-01-01/meta-data": "aliyun",
    "metadata/instance": "azure",
    "latest/meta-data": "ec2",
    "2018-09-24/meta-data": "ec2",
    "computeMetadata/v1": "gcp",
    "opc/v2": "oci",
}

EC2_TOKEN = "AQAAALH-k7i18JMkK-ORLZQfAa7nkNjQbKwpQPExNHqzk1oL_7eh-A=="


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
    raise ValueError(f'Not a boolean value ("{s0}")')


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
        v = self.rfile.read(length).decode("utf-8")
        dbg('receive "%s"' % (v,))
        return v

    def _path_to_provider(self):
        """
        Returns: the provider (None if error) and the error message (None if success).
        """
        path = self.path.strip().strip("/")

        provider = None
        for path_prefix in PATHS_TO_PROVIDERS_MAP:
            if path.startswith(path_prefix):
                provider = PATHS_TO_PROVIDERS_MAP[path_prefix]
                break

        if provider is None:
            return None, f"no provider matches for {self.path}"
        elif provider not in self.server.config_get_providers():
            return None, f"{provider} provider is disabled"

        return provider, None

    def do_GET(self):
        dbg("GET %s" % (self.path,))
        path = self.path.split("?")[0]
        path = path.strip().strip("/")

        provider, err_msg = self._path_to_provider()
        if not provider:
            self._response_and_end(404, write=err_msg)
            return

        # If the path has been added to the config's "delay" list, add a 0.5 delay.
        if path in self.server._config.get("delay", []):
            time.sleep(0.5)

        if resource := self.server.get_resource(provider, self.path):
            mode = PROVIDERS.get(provider)
            if mode == "json":
                response = json.dumps(resource)
            elif type(resource) is dict:
                response = "\n".join(key for key in resource)
            elif type(resource) is list:
                response = "\n".join(str(i) for i in range(len(resource)))
            else:
                response = str(resource)

            self._response_and_end(200, write=response)
            return

        self._response_and_end(404)

    def do_PUT(self):
        dbg("PUT %s" % (self.path,))
        path = self.path.strip().strip("/")

        # Special path to add configs to the Mock server
        if path.startswith(".nmtest/"):
            conf_name = path.removeprefix(".nmtest/")
            data = self._read()
            try:
                data = json.loads(data)
            except:
                pass
            self.server._config[conf_name] = data
            self._response_and_end(201)
            return
        # Special path for EC2 secret token. It's PUT but must behave like GET. \_(ツ)_/
        elif path.startswith("latest/api/token"):
            if "ec2" in self.server.config_get_providers():
                self._response_and_end(200, write=EC2_TOKEN)
            else:
                self._response_and_end(404)
            return

        provider, err_msg = self._path_to_provider()
        if not provider:
            self._response_and_end(404, write=err_msg)
            return

        try:
            content = self._read()
            resource = json.loads(content)
        except json.JSONDecodeError:  # Not JSON? Probably a plain string
            resource = content
        self.server.set_resource(provider, self.path, resource)
        self._response_and_end(201)

    def do_DELETE(self):
        dbg("DELETE %s" % (self.path,))

        provider, err_msg = self._path_to_provider()
        if not provider:
            self._response_and_end(404, write=err_msg)
            return

        ok = self.server.del_resource(provider, self.path)
        self._response_and_end(204 if ok else 404)


class SocketHTTPServer(ThreadingHTTPServer):
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
        create_default=True,
    ):
        BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.socket = socket
        self.server_address = self.socket.getsockname()
        self._resources = resources if resources is not None else {}
        self._config = {}
        self._create_id_resources()
        if create_default:
            self._create_default_resources()

    def _split_path(self, path):
        path = path.split("?")[0]  # Ignore GET query arguments
        return path.strip().strip("/").split("/")

    def config_get_providers(self):
        conf = self._config.get("providers", None)
        if not conf:
            return PROVIDERS.keys()
        parsed = [s.lower() for s in conf.split(" ")]
        assert all(p in PROVIDERS for p in parsed)
        return parsed

    def get_resource(self, provider, path):
        if provider not in PROVIDERS:
            raise ValueError(f"{provider} is not a valid provider")
        if provider not in self.config_get_providers():
            raise ValueError(f"{provider} provider is disabled")
        if provider not in self._resources:
            return None

        path = self._split_path(path)

        resource = self._resources[provider]
        for p in path:
            if type(resource) is dict:
                if p not in resource:
                    return None
                resource = resource[p]
            elif type(resource) is list:
                if not p.isnumeric() or int(p) >= len(resource):
                    return None
                resource = resource[int(p)]
            else:
                return None

        return resource

    def set_resource(self, provider, path, resource):
        if provider not in PROVIDERS:
            raise ValueError(f"{provider} is not a valid provider")

        path = self._split_path(path)

        # First, find the parent element
        parent = self._resources.setdefault(provider, {})
        for i, p in enumerate(path):
            if p.isnumeric() and type(parent) is not list:
                raise ValueError("Numeric key used on non-list /" + "/".join(path[:i]))
            elif not p.isnumeric() and type(parent) is not dict:
                raise ValueError("String key used on non-dict /" + "/".join(path[:i]))
            elif p.isnumeric() and type(parent) is list and int(p) > len(parent):
                raise IndexError(f"Index {p} out of range on /" + "/".join(path[:i]))

            # Last element of the path, we found the parent
            if i == len(path) - 1:
                break

            # If the next element doesn't exist, we create it. To determine if we create
            # it as list or dict, we check the next element of the path to see what
            # kind of key it is: numeric or string.
            next_default = [] if path[i + 1].isnumeric() else {}
            if not p.isnumeric():
                parent = parent.setdefault(p, next_default)
            else:
                if int(p) == len(parent):
                    parent.append(next_default)
                parent = parent[int(p)]

        # Add the resource to the parent, or replace if if existed
        if not p.isnumeric():
            parent[p] = resource
        elif int(p) < len(parent):
            parent[int(p)] = resource
        else:
            parent.append(resource)

    def del_resource(self, provider, path):
        if provider not in PROVIDERS:
            raise ValueError(f"{provider} is not a valid provider")

        path = self._split_path(path)

        parent = self._resources.setdefault(provider, {})
        for i, p in enumerate(path):
            if type(parent) is dict and p not in parent:
                return False
            elif type(parent) is list and (not p.isnumeric() or int(p) >= len(parent)):
                return False

            if i == len(path) - 1:
                break

            if type(parent) is dict:
                parent = parent[p]
            elif type(parent) is list:
                parent = parent[int(p)]
            else:
                return False

        del parent[p if type(parent) is dict else int(p)]
        return True

    def _create_id_resources(self):
        self.set_resource("ec2", "latest/meta-data", "ami-id\n")
        self.set_resource("gcp", "computeMetadata/v1/instance/id", "ami-id")
        self.set_resource("oci", "opc/v2/instance", "ami-id")

    def _create_default_resources(self):
        mac1 = "cc:00:00:00:00:01"
        mac2 = "cc:00:00:00:00:02"
        ip1 = "172.16.0.1"
        ip2 = "172.17.0.2"
        subnet1 = "172.16.0.0"
        subnet2 = "172.17.0.0"
        netmask1 = "255.255.0.0"
        netmask2 = "255.255.0.0"
        prefix1 = "16"
        prefix2 = "16"
        gw1 = "172.16.255.254"
        gw2 = "172.17.255.254"

        self.set_resource(
            "aliyun",
            "2016-01-01/meta-data/network/interfaces/macs",
            {
                mac1: {
                    "vpc-cidr-block": subnet1 + "/" + prefix1,
                    "private-ipv4s": [ip1],
                    "primary-ip-address": ip1,
                    "netmask": netmask1,
                    "gateway": gw1,
                },
                mac2: {
                    "vpc-cidr-block": subnet2 + "/" + prefix2,
                    "private-ipv4s": [ip2],
                    "primary-ip-address": ip2,
                    "netmask": netmask2,
                    "gateway": gw2,
                },
            },
        )

        self.set_resource(
            "azure",
            "metadata/instance/network/interface",
            [
                {
                    "macAddress": mac1,
                    "ipv4": {
                        "ipAddress": [{"privateIpAddress": ip1}],
                        "subnet": [{"address": subnet1, "prefix": prefix1}],
                    },
                },
                {
                    "macAddress": mac1,
                    "ipv4": {
                        "ipAddress": [{"privateIpAddress": ip2}],
                        "subnet": [{"address": subnet2, "prefix": prefix2}],
                    },
                },
            ],
        )

        self.set_resource(
            "ec2",
            "2018-09-24/meta-data/network/interfaces/macs",
            {
                mac1: {
                    "subnet-ipv4-cidr-block": subnet1 + "/" + prefix1,
                    "local-ipv4s": ip1,
                },
                mac2: {
                    "subnet-ipv4-cidr-block": subnet2 + "/" + prefix2,
                    "local-ipv4s": ip2,
                },
            },
        )

        self.set_resource(
            "gcp",
            "computeMetadata/v1/instance/network-interfaces/",
            [
                {
                    "mac": mac1,
                    "forwarded-ips": [ip1],
                },
                {
                    "mac": mac2,
                    "forwarded-ips": [ip2],
                },
            ],
        )

        self.set_resource(
            "oci",
            "opc/v2/vnics",
            [
                {
                    "vnicId": "example.id.1",
                    "privateIp": ip1,
                    "vlanTag": 0,
                    "macAddr": mac1,
                    "virtualRouterIp": gw1,
                    "subnetCidrBlock": subnet1 + "/" + prefix1,
                    "nicIndex": 0,
                },
                {
                    "vnicId": "example.id.2",
                    "privateIp": ip2,
                    "vlanTag": 0,
                    "macAddr": mac2,
                    "virtualRouterIp": gw2,
                    "subnetCidrBlock": subnet2 + "/" + prefix1,
                    "nicIndex": 1,
                },
                {
                    "vnicId": "example.id.vlan.100",
                    "privateIp": "172.31.0.1",
                    "vlanTag": 100,
                    "macAddr": "ff:00:00:00:00:01",
                    "virtualRouterIp": "172.31.255.254",
                    "subnetCidrBlock": "172.31.0.0/16",
                    "nicIndex": 1,
                },
            ],
        )


create_default_resources = True
port = 0
for arg in sys.argv[1:]:
    if arg == "--empty":
        create_default_resources = False
    else:
        port = int(arg)

# See sd_listen_fds(3)
fileno = os.getenv("LISTEN_FDS")
if fileno is not None:
    if fileno != "1":
        raise Exception("Bad LISTEN_FDS")
    s = socket.socket(fileno=3)
else:
    addr = ("localhost", port)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(addr)

httpd = SocketHTTPServer(
    None,
    MockCloudMDRequestHandler,
    socket=s,
    create_default=create_default_resources,
)

print("Listening on http://%s:%d" % (httpd.server_address[0], httpd.server_address[1]))
httpd.server_activate()

httpd.serve_forever()
httpd.server_close()
