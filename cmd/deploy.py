#!/usr/bin/env python3

import argparse
import json
import os.path
import socket
import struct
import sys
import yaml

try:
    # Cython provides PKGLIBDIR.
    sys.path.insert(0, PKGLIBDIR)
except NameError:
    # Extend sys.path to include the parent directory. This is necessary because this
    # script resides in a subdirectory, and we need to import shared modules located
    # in the project's top-level 'lib' directory.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

import _clearly as _clearly


## Main ##

def main():
    ap = _clearly.ArgumentParser(
        description="Deploy an application to the cluster.",
        epilog="""The deploy command reads a Docker Compose file and deploys
                  the herein defined services across the cluster.""")

    ap.add_argument("-f", "--file", metavar="FILE", default="docker-compose.yml",
                    help="specify alternate file (default: docker-compose.yml)")
    ap.add_argument("name", metavar="NAME", help="application name")

    # Parse arguments.
    if len(sys.argv) < 2:
        ap.print_help(file=sys.stderr)
        _clearly.exit(1)
    cli = ap.parse_args()

    # Initialize.
    _clearly.init(cli)

    # Check if compose file exists.
    if not os.path.isfile(cli.file):
        _clearly.FATAL("open %s: no such file or directory" % cli.file)

    # Read compose file.
    try:
        with open(cli.file, 'r') as f:
            compose_data = f.read()
    except Exception as e:
        _clearly.FATAL("open %s: %s" % (cli.file, e))

    # Send message to daemon.
    try:
        SOCK_PATH = "/var/lib/clearly/clearly.sock"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(SOCK_PATH)
        
        msg = {
            "type": "DEPLOY",
            "payload": {
                "name": cli.name,
                "file": compose_data
            },
            "reply_to": None
        }
        
        sock.send(json.dumps(msg).encode('utf-8'))
        
        # Wait for reply.
        sock.settimeout(10.0)
        data, addr = sock.recvfrom(2048)
        reply = json.loads(data.decode('utf-8'))
        
        if reply.get("status") == "error":
            _clearly.FATAL("failed: %s" % reply.get("message", "unknown error"))
        
        _clearly.INFO("done")
        
    except socket.timeout:
        _clearly.FATAL("connect %s: connection timed out" % SOCK_PATH)
    except FileNotFoundError:
        _clearly.FATAL("connect %s: no such file or directory" % SOCK_PATH)
    except Exception as e:
        _clearly.FATAL("connect %s: %s" % (SOCK_PATH, e))
    finally:
        sock.close()

    _clearly.exit(0)


## Bootstrap ##

if __name__ == "__main__":
    try:
        main()
    except _clearly.Fatal_Error as x:
        _clearly.warnings_dump()
        _clearly.ERROR(*x.args, **x.kwargs)
        _clearly.exit(1)
