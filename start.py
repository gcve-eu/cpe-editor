#!/usr/bin/env python3
"""Start the CPE Editor Flask app with Gunicorn on IPv4 and IPv6."""

from __future__ import annotations

import os
import socket
import sys


def _listen_socket(family: socket.AddressFamily, host: str, port: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    sock.set_inheritable(True)
    return sock


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    host_ipv4 = os.environ.get("HOST_IPV4", "0.0.0.0")
    host_ipv6 = os.environ.get("HOST_IPV6", "::")

    ipv4_sock = _listen_socket(socket.AF_INET, host_ipv4, port)
    ipv6_sock = _listen_socket(socket.AF_INET6, host_ipv6, port)

    command = [
        "gunicorn",
        "--bind",
        f"fd://{ipv4_sock.fileno()}",
        "--bind",
        f"fd://{ipv6_sock.fileno()}",
        "wsgi:app",
        *sys.argv[1:],
    ]
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
