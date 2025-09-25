#!/usr/bin/env python3

import socket
import struct
import json
import yaml
import time
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
import _runtime as _runtime


## Main ##

def main():
    runtime = _runtime.Runtime()
    runtime.start()

    socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    socket.bind("/var/lib/clearly/clearly.sock")
    socket.setblocking(False)

    # Keep alive.
    while True:
        try:
            data, addr = socket.recvfrom(2048)
            msg = json.loads(data.decode('utf-8', errors='ignore'))

            # Extract mandatory fields.
            payload = msg.get("payload")
            reply_to = msg.get("reply_to")

            match msg.get("type"):
                case "LIST":
                    status = "ok"
                    message = {}

                    # List.
                    try:
                        for node_id, metadata in runtime.cluster.items():
                            # Skip expired nodes.
                            if now - metadata["timestamp"] > _runtime.PEER_TTL: 
                                continue
                            # Loop through containers.
                            for k, v in metadata["containers"].items():
                                # Skip removed containers.
                                if v.get("status") != "removed":
                                    message[k] = {
                                        "node": node_id,
                                        **v
                                    }
                    except Exception as e:
                        status = "error"
                        message = str(e)

                case "DEPLOY":
                    name = payload.get("name")
                    file = yaml.safe_load(payload.get("file"))
                    status = "ok"
                    message = None

                    # Deploy.
                    try:
                        runtime.deploy({
                            "type": "DEPLOY",
                            "data": {
                                "id": name,
                                "services": file["services"]
                            },
                            "timestamp": time.time()
                        })
                    except Exception as e:
                        status = "error"
                        message = str(e)
                
                case _:
                    status = "error"
                    message = "malformed"
                    
                # Reply.
                socket.sendmsg(
                    [json.dumps({"status": status, "message": message}).encode('utf-8')],
                    [(socket.SOL_SOCKET, struct.pack('i', socket.fileno()))],
                    0, reply_to
                )
        except BlockingIOError:
            time.sleep(0.02)
            continue
        except Exception as e:
            _clearly.WARNING(f"clearly.sock: {e}")
            time.sleep(0.1)
            continue

if __name__ == "__main__":
    main()