#!/usr/bin/env python3

import websockets
import socket
import struct
import select
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


## Constants ##

SOCK_PATH = "/var/lib/clearly"


## Main ##

def main():
    runtime = _runtime.Runtime()

    # Socket Allocation.
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(SOCK_PATH + "/clearly.sock"):
        os.unlink(SOCK_PATH + "/clearly.sock")
    unix.bind(SOCK_PATH + "/clearly.sock")
    unix.setblocking(False)
    unix.listen()
    ws = None

    # State.
    unix_clients = []
    ws_time = 0

    while True:
        if ws is None and (time.time() - ws_time) >= 10:
            try:
                token = open("/var/lib/clearly/clearly.token").read().strip()
                url = open("/var/lib/clearly/clearly.url").read().strip()
                ws = websockets.connect(f"wss://{url}?token={token}")
            except:
                ws_time = time.time()
                pass
        
        # Select sockets.
        rlist = [unix] + unix_clients + ([ws] if ws else [])
        selectable = select.select(rlist, [], [], 0.02)[0]
        
        # Handle messages.
        for selected in selectable:
            try:
                if selected is unix:
                    # Accept client.
                    conn, _ = unix.accept()
                    conn.setblocking(False)
                    unix_clients.append(conn)
                    continue

                if selected in unix_clients:
                    # Existing client.
                    data = selected.recv(4096)
                    if not data:
                        unix_clients.remove(selected)
                        selected.close()
                        continue
                    msg = json.loads(data.decode('utf-8', errors='ignore'))
                else:
                    # WebSocket.
                    message = ws.recv()
                    msg = json.loads(message)

                # Mandatory fields.
                payload = msg.get("payload")
                type = msg.get("type")
                id = msg.get("id")
                
                # Handle.
                status = "ok"
                try:
                    if type == "LIST":
                        message = runtime.list()
                    elif type == "STOP":
                        name = payload.get("name")
                        message = runtime.stop(name)
                    elif type == "START":
                        message = runtime.start(payload)
                    elif type == "DEPLOY":
                        name = payload.get("name")
                        file = yaml.safe_load(payload.get("file"))
                        message = runtime.deploy({
                            "type": "DEPLOY",
                            "data": {
                                "id": name,
                                "services": file["services"]
                            },
                            "timestamp": time.time()
                        })
                    elif type == "REPLY":
                        continue
                    else:
                        status = "error"
                        message = "unknown type"
                except Exception as e:
                    status = "error"
                    message = str(e)
                
                # Reply.
                bytes = json.dumps({
                    "type": "REPLY",
                    "payload": {"status": status, "message": message},
                    "id": id
                }).encode('utf-8')

                if selected in unix_clients:
                    selected.sendall(bytes)
                else:
                    ws.send(bytes)
                    
            except Exception as e:
                if selected == ws:
                    ws = None  # Reconnect.
                else:
                    if selected in unix_clients:
                        try:
                            unix_clients.remove(selected)
                        except ValueError:
                            pass
                        try:
                            selected.close()
                        except:
                            pass
                _clearly.WARNING(f"socket: {e}")
                continue

if __name__ == "__main__":
    main()