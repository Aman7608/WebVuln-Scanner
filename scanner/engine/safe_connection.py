"""
Safe connections - SSRF protection on every single connection.

Checking the target's IP address once, before the scan starts, is not
enough. An attacker who controls a domain can make it point to a normal
internet address during the check, and then switch it to an internal
address like 127.0.0.1 or 10.0.0.5 a second later ("DNS rebinding").
The scanner would then attack the server's own private network.

So we hook into the place where the requests library actually opens a
network connection:
  1. look up the host name ourselves,
  2. check EVERY address with target_manager.is_connection_allowed(),
  3. connect to exactly the address we checked.

Because we connect to the checked address, the name cannot change in between.
HTTPS still works normally: the certificate is checked against the host name.

How it is wired up (you do not need to understand urllib3 to use it):
requests -> HTTPAdapter -> urllib3 connection pool -> connection._new_conn()
We replace _new_conn() in our own connection classes and tell the adapter to
use pools that create those connections.
"""

import logging
import socket

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError
from urllib3.util import connection as urllib3_connection

from scanner import target_manager

logger = logging.getLogger(__name__)


class BlockedAddressError(NewConnectionError):
    """Raised when a host name points to an address the scanner may not contact."""


class GuardedConnectionMixin:
    def _new_conn(self):
        host = self._dns_host
        try:
            results = socket.getaddrinfo(host, self.port, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise NewConnectionError(self, f"Could not resolve {host}: {error}") from error

        addresses = list(dict.fromkeys(result[4][0] for result in results))
        blocked = [ip for ip in addresses if not target_manager.is_connection_allowed(host, ip)]
        if blocked or not addresses:
            logger.warning("Blocked connection to %s (%s)", host, ", ".join(blocked) or "no address")
            raise BlockedAddressError(
                self, f"Blocked: {host} points to a forbidden address ({', '.join(blocked)})")

        try:
            # Connect to the exact address we just checked
            return urllib3_connection.create_connection(
                (addresses[0], self.port), self.timeout,
                source_address=self.source_address, socket_options=self.socket_options)
        except OSError as error:
            raise NewConnectionError(self, f"Failed to establish a new connection: {error}") from error


class GuardedHTTPConnection(GuardedConnectionMixin, HTTPConnection):
    pass


class GuardedHTTPSConnection(GuardedConnectionMixin, HTTPSConnection):
    pass


class GuardedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = GuardedHTTPConnection


class GuardedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = GuardedHTTPSConnection


class GuardedAdapter(HTTPAdapter):
    """A requests adapter whose connections all go through the address check."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": GuardedHTTPConnectionPool,
            "https": GuardedHTTPSConnectionPool,
        }


def protect_session(session):
    """Make every request of this requests.Session use guarded connections."""
    adapter = GuardedAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    # Ignore HTTP(S)_PROXY settings: a proxy would make the connection for us
    # and our address check would be skipped.
    session.trust_env = False
    return session
