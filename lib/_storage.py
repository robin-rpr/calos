#!/usr/bin/env python3

import os
import logging
import subprocess
import socket
from time import sleep

logger = logging.getLogger(__name__)

class Storage:
    """DRBD/GFS2 Distributed Storage."""

    def __init__(self, name, image_dir, mount_dir, size='10G'):
        self.drbd_device = '/dev/drbd0'
        self.image_dir = image_dir
        self.mount_dir = mount_dir
        self.loop_device = None
        self.name = name
        self.size = size
        self.nodes = {}

    def _setup_image(self):
        """Ensures the backing device for DRBD is set up."""
        image_path = os.path.join(self.image_dir, f"{self.name}.img")

        # Create the backing file if it doesn't exist
        if not os.path.exists(image_path):
            logger.info(f"Creating backing file at {image_path} with size {self.size}")
            subprocess.run(['truncate', '-s', self.size, image_path], capture_output=True, text=True, check=True)

        # Check if it's already associated with a loop device
        result = subprocess.run(['losetup', '-j', image_path], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout:
            self.loop_device = result.stdout.split(':')[0]
            logger.info(f"Backing file already associated with {self.loop_device}")
            return

        # Set up the loop device
        logger.info("Setting up loop device...")
        result = subprocess.run(['losetup', '--find', '--show', image_path], capture_output=True, text=True, check=True)
        self.loop_device = result.stdout.strip()
        logger.info(f"Loop device {self.loop_device} created for {image_path}")

    def set_nodes(self, nodes):
        """Generates and applies DRBD configuration from the list of nodes."""
        logger.info("Generating new DRBD configuration.")
        config_path = f"/etc/drbd.d/{self.name}.res"
        self.nodes = nodes
        
        # Determine hostnames from service names
        hostnames = [name.split('.')[0].replace(f"clearly-", "") for name in nodes.keys()]
        
        config_content = f"""
resource {self.name} {{
    protocol C;

    startup {{
        wfc-timeout 15;
        degr-wfc-timeout 15;
    }}

    net {{
        allow-multiple-primaries yes;
        shared-secret "clearly_secret";
        after-sb-0pri discard-zero-changes;
        after-sb-1pri discard-secondary;
        after-sb-2pri disconnect;
    }}
"""
        for name, details in nodes.items():
            hostname = details['server'].split('.')[0]
            ip_address = details['address']
            config_content += f"""
    on {hostname} {{
        device {self.drbd_device};
        disk {self.loop_device};
        address {ip_address}:7789;
        meta-disk internal;
    }}
"""
        config_content += "}\n"

        logger.info(f"Writing DRBD config to {config_path}")
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        subprocess.run(['drbdadm', 'adjust', self.name], capture_output=True, text=True, check=True)

    def start(self, nodes):
        """Brings the DRBD resource online and mounts the GFS2 filesystem."""
        self._setup_image()

        # Check DRBD resource status
        status_result = subprocess.run(['drbdadm', 'status', self.name], capture_output=True, text=True, check=False)
        if 'does not exist' in status_result.stderr:
            logger.info(f"Creating metadata for DRBD resource {self.name}")
            subprocess.run(['drbdadm', 'create-md', self.name], capture_output=True, text=True, check=True)

        logger.info(f"Bringing up DRBD resource {self.name}")
        self._run_command(['drbdadm', 'up', self.name])

        # This logic is simplified. A real cluster needs a proper bootstrap/election process.
        # We assume the node with the lexicographically smallest hostname initializes the filesystem.
        all_hostnames = sorted([node['server'].split('.')[0] for node in self.nodes.values()])
        
        if self.hostname == all_hostnames[0]:
            self._run_command(['drbdadm', 'primary', '--force', self.name])
            # Check if filesystem exists
            check_fs_result = self._run_command(['blkid', '-p', self.drbd_device], check=False)
            if 'TYPE="gfs2"' not in check_fs_result.stdout:
                logger.info("No GFS2 filesystem found. Creating one...")
                subprocess.run([
                    'mkfs.gfs2',
                    '-p', 'lock_dlm',
                    '-t', f"clearly:{self.name}",
                    self.drbd_device
                ], capture_output=True, text=True, check=True)
            else:
                logger.info("GFS2 filesystem already exists.")
        else:
            # Other nodes wait and then go primary. In a real scenario, this would
            # be managed by Pacemaker/Corosync.
            sleep(10) # wait for first node to create fs
            subprocess.run(['drbdadm', 'primary', self.name], capture_output=True, text=True, check=True)
        
        # Check if already mounted
        if not os.path.ismount(self.mount_dir):
            logger.info(f"Mounting {self.drbd_device} to {self.mount_dir}")
            subprocess.run(['mount', '-t', 'gfs2', self.drbd_device, self.mount_dir], capture_output=True, text=True, check=True)
        else:
            logger.info(f"{self.mount_dir} is already mounted.")

    def stop(self):
        """Unmounts the GFS2 filesystem and brings the DRBD resource offline."""
        if os.path.ismount(self.mount_dir):
            subprocess.run(['umount', self.mount_dir], capture_output=True, text=True, check=True)
        
        subprocess.run(['drbdadm', 'down', self.name], capture_output=True, text=True, check=True)
        
        if self.loop_device:
            subprocess.run(['losetup', '-d', self.loop_device], capture_output=True, text=True, check=True)
