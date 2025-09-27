#!/usr/bin/env python3

import argparse
import socket
import struct
import random
import time
import yaml
import json
import sys
import os

try:
    # Cython provides PKGLIBDIR.
    sys.path.insert(0, PKGLIBDIR)
except NameError:
    # Extend sys.path to include the parent directory. This is necessary because this
    # script resides in a subdirectory, and we need to import shared modules located
    # in the project's top-level 'lib' directory.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

import _clearly as _clearly


## Constants ##

SOCK_PATH = "/var/lib/clearly"
SOCK_NONCE = random.randint(0, 1000000)


## Main ##

def main():
    ap = argparse.ArgumentParser(
        description="Deploy an application to the cluster.",
        epilog="""The deploy command reads a Docker Compose file and deploys
                  the herein defined services across the cluster.""")

    ap.add_argument("-f", "--file", metavar="FILE", default="docker-compose.yml",
                    help="specify alternate file (default: docker-compose.yml)")
    ap.add_argument("name", metavar="NAME", help="application name")

    # Parse arguments.
    cli = ap.parse_args()

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
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(SOCK_PATH + "/clearly.sock")
        id = random.randint(0, 1000000)
        
        msg = {
            "type": "DEPLOY",
            "payload": {
                "name": cli.name,
                "file": compose_data
            },
            "id": id
        }
        
        sock.sendall(json.dumps(msg).encode('utf-8'))

        # Wait for reply.
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                msg = json.loads(data.decode('utf-8'))

                # Mandatory fields.
                payload = msg.get("payload")
                type = msg.get("type")
                id = msg.get("id")

                # Handle.
                if type == "REPLY" and id == id:
                    break
            except BlockingIOError:
                time.sleep(0.1)
                continue
            except Exception as e:
                raise
        
        if payload.get("status") == "error":
            _clearly.FATAL("failed: %s" % payload.get("message"))
        
        _clearly.INFO("done")
        
    except socket.timeout:
        _clearly.FATAL("connection to the daemon timed out")
    except socket.error:
        _clearly.FATAL("couldn't connect to the daemon")
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
