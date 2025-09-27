#!/usr/bin/env python3

import argparse
import os.path
import random
import socket
import struct
import time
import json
import sys

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


## Main ##

def main():
    ap = argparse.ArgumentParser(
        description="List containers.",
        epilog="""The list command shows all containers currently managed by the Clearly
                  runtime, including their container ID, image, IP address, and current status.""")

    ap.add_argument("--format", metavar="FORMAT", 
                    default="table {{.ID}}\t\t{{.Image}}\t\t{{.IP}}\t\t{{.Status}}\t\t{{.Ports}}",
                    help="format output using a Go template (default: table format)")
    ap.add_argument("--no-trunc", action="store_true",
                    help="don't truncate output")

    # Parse arguments.
    cli = ap.parse_args()

    # Send message to daemon.
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(SOCK_PATH + "/clearly.sock")
        id = random.randint(0, 1000000)

        msg = {
            "type": "LIST",
            "payload": {},
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
        
        containers = payload.get("message", {})
        
        # Format and display output
        if cli.format.startswith("table "):
            _display_table(containers, cli.format[6:], cli.no_trunc)
        else:
            _display_custom(containers, cli.format, cli.no_trunc)
        
    except socket.timeout:
        _clearly.FATAL("connection to the daemon timed out")
    except socket.error:
        _clearly.FATAL("couldn't connect to the daemon")
    except Exception as e:
        _clearly.FATAL(str(e))
    finally:
        sock.close()

    _clearly.exit(0)


## Functions ##

def _display_table(containers, format_template, no_trunc):
    """Display containers in table format."""
    
    # Parse format template
    fields = []
    for field in format_template.split('\t'):
        if field.startswith('{{.') and field.endswith('}}'):
            field_name = field[3:-2]
            fields.append(field_name)
        else:
            fields.append(field)
    
    # Calculate column widths
    widths = {}
    for i, field in enumerate(fields):
        if field in ['ID', 'Image', 'IP', 'Status', 'Ports', 'Labels', 'Node']:
            # Start with header width
            if field == 'ID':
                header = 'CONTAINER ID'
            else:
                header = field.upper()
            widths[i] = len(header)
            
            # Check container data widths
            for container_id, container in containers.items():
                value = _get_field_value(container, field, no_trunc)
                widths[i] = max(widths[i], len(value))
    
    # Print header
    header_parts = []
    for i, field in enumerate(fields):
        if field in ['ID', 'Image', 'IP', 'Status', 'Ports', 'Labels', 'Node']:
            if field == 'ID':
                header = 'CONTAINER ID'
            else:
                header = field.upper()
            width = widths.get(i, len(header))
            header_parts.append(f"%-{width}s" % header)
        else:
            header_parts.append(field)
    print('\t'.join(header_parts))
    
    # Print containers
    for container_id, container in containers.items():
        row_parts = []
        for i, field in enumerate(fields):
            if field in ['ID', 'Image', 'IP', 'Status', 'Ports', 'Labels', 'Node']:
                value = _get_field_value(container, field, no_trunc)
                width = widths.get(i, len(value))
                row_parts.append(f"%-{width}s" % value)
            else:
                row_parts.append(field)
        print('\t'.join(row_parts))

def _display_custom(containers, format_template, no_trunc):
    """Display containers using custom format template."""
    for container_id, container in containers.items():
        output = format_template
        for field in ['ID', 'Image', 'IP', 'Status', 'Ports', 'Labels', 'Node']:
            placeholder = f"{{{{{field}}}}}"
            if placeholder in output:
                value = _get_field_value(container, field, no_trunc)
                output = output.replace(placeholder, value)
        print(output)

def _get_field_value(container, field, no_trunc):
    """Get formatted field value for container."""
    if field == 'ID':
        value = container.get('id', '')
        if not no_trunc and len(value) > 12:
            value = value[:12]
    elif field == 'Image':
        value = container.get('image', '')
        if not no_trunc and len(value) > 20:
            value = value[:20]
    elif field == 'IP':
        value = container.get('ip', '')
    elif field == 'Status':
        value = container.get('status', '')
    elif field == 'Ports':
        ports = container.get('ports', {})
        if ports:
            port_list = []
            for host_port, container_port in ports.items():
                if container_port:
                    port_list.append(f"{host_port}:{container_port}")
                else:
                    port_list.append(host_port)
            value = ', '.join(port_list)
        else:
            value = ''
    elif field == 'Labels':
        labels = container.get('labels', {})
        if labels:
            label_list = []
            for key, val in labels.items():
                if val:
                    label_list.append(f"{key}={val}")
                else:
                    label_list.append(key)
            value = ', '.join(label_list)
        else:
            value = ''
    elif field == 'Node':
        value = container.get('node', '')
    else:
        value = ''
    
    return value or '-'


## Bootstrap ##

if __name__ == "__main__":
    try:
        main()
    except _clearly.Fatal_Error as x:
        _clearly.warnings_dump()
        _clearly.ERROR(*x.args, **x.kwargs)
        _clearly.exit(1)
