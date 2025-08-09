import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import threading
import requests
import signal
import copy
import time
import os


## Classes ##

class Syncthing:
    """
    A wrapper around the Syncthing daemon.
    
    Example:
        syncthing = Syncthing(home_dir=Path("/var/lib/clearly"))
        syncthing.add_folder("clearly", "/run/clearly", label="runtime", type="sendreceive")
        syncthing.add_peer("192.168.1.100", "tcp://192.168.1.100:22000")
        syncthing.start()
    """
    def __init__(self, home_dir=Path.home()):
        """
        Initialize the Syncthing daemon.
        
        Args:
            home_dir: Directory for the Syncthing configuration
        """
        self.config_file = home_dir / "config.xml"
        self.home_dir = home_dir
        self.thread = None

        # Ensure config file exists
        subprocess.run(
            ['syncthing', 'generate', '--home', str(self.home_dir),
            '--no-default-folder', '--skip-port-probing'],
            check=True
        )

    def set_options(self, **kwargs):
        """
        Set options in the Syncthing configuration.
        
        Args:
            **kwargs: Option names and values to set
            
        Example:
            set_options(startBrowser=False, maxSendKbps=1000, 
                       globalAnnounceEnabled=False)
        """
        tree = ET.parse(self.config_file)
        root = tree.getroot()

        # Handle special case for guiEnabled
        if "guiEnabled" in kwargs:
            gui = root.find("./gui")
            if gui is not None:
                gui.set("enabled", str(kwargs["guiEnabled"]).lower())
                del kwargs["guiEnabled"]

        # Find the options element
        options = root.find("./options")
        if options is None:
            # Create options element if it doesn't exist
            options = ET.SubElement(root, "options")
        
        # Update each option
        for key, value in kwargs.items():
            option_elem = options.find(f"./{key}")
            new_value = str(value).lower() if isinstance(value, bool) else str(value)
            if option_elem is not None:
                # Update existing option
                option_elem.text = new_value
            else:
                # Create new option element
                new_option = ET.SubElement(options, key)
                new_option.text = new_value
        
        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)
        
    def add_peer(self, device_id, ip):
        """Add a peer to the Syncthing configuration."""
        tree = ET.parse(self.config_file)
        root = tree.getroot()
        
        # Skip if already present
        if any(d.attrib["id"] == device_id for d in root.findall("device")):
            return

        # Copy default device configuration
        defaults = root.find("./defaults")
        default_device = defaults.find("./device")
        device = ET.SubElement(root, "device")
        
        # Copy all attributes from default device
        for key, value in default_device.attrib.items():
            device.set(key, value)
        
        # Override with specific values
        device.set("id", device_id)
        device.set("name", device_id)
        
        # Copy all child elements from default device
        for child in default_device:
            child_copy = ET.SubElement(device, child.tag)
            # Copy attributes
            for key, value in child.attrib.items():
                child_copy.set(key, value)
            # Copy text content
            if child.text:
                child_copy.text = child.text
        
        # Update the address element with the specific IP
        address_elem = device.find("./address")
        address_elem.text = f"tcp://{ip}:22000"

        # Link device to all folders
        for folder in root.findall("folder"):
            ET.SubElement(folder, "device", {"id": device_id})

        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    def remove_peer(self, device_id):
        """Remove a peer from the Syncthing configuration."""
        tree = ET.parse(self.config_file)
        root = tree.getroot()

        # Remove device from root
        for dev in root.findall("device"):
            if dev.attrib.get("id") == device_id:
                root.remove(dev)

        # Remove device from all folders
        for folder in root.findall("folder"):
            for dev in folder.findall("device"):
                if dev.attrib.get("id") == device_id:
                    folder.remove(dev)

        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    def add_folder(self, id, path, **kwargs):
        """
        Add a new folder to the Syncthing configuration.
        
        Copies the default folder template and allows overriding both attributes
        and child element values.
        
        Args:
            id (str): Unique identifier for the folder
            path (str): Local filesystem path for the folder
            **kwargs: Folder attributes and child elements to override
                     Attributes: label="My Folder", type="receiveonly"
                     Child elements: copiers=4, hashers=2, maxConflicts=5
        
        Example:
            add_folder("docs", "/home/docs", label="Documents", 
                      copiers=4, hashers=2, paused=True)
        """
        tree = ET.parse(self.config_file)
        root = tree.getroot()
        
        # Skip if folder already exists
        if any(f.attrib.get("id") == id for f in root.findall("folder")):
            return
        
        # Copy default folder template
        default_folder = root.find("./defaults/folder")
        folder = copy.deepcopy(default_folder)
        
        # Set required attributes
        folder.set("id", id)
        folder.set("path", path)
        
        # Apply custom options
        for key, value in kwargs.items():
            # Try to find child element first
            child_elem = folder.find(f"./{key}")
            if child_elem is not None:
                # Update child element text content
                child_elem.text = str(value)
            else:
                # Set as folder attribute
                folder.set(key, str(value))
        
        # Add to configuration
        root.insert(0, folder)
        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    def remove_folder(self, id):
        """Remove a folder from the Syncthing configuration."""
        tree = ET.parse(self.config_file)
        root = tree.getroot()

        # Remove the folder
        for folder in root.findall("folder"):
            if folder.attrib.get("id") == id:
                root.remove(folder)

        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    @property
    def device_id(self):
        """Get the device ID of the Syncthing device."""
        return subprocess.check_output(['syncthing', '--device-id', '--home',
                                        str(self.home_dir)]).decode('utf-8').strip()

    def serve_forever(self):
        """Start the Syncthing daemon."""
        subprocess.run(
            ['syncthing', 'serve', '--home', str(self.home_dir)],
            check=True
        )

    def restart(self):
        """Restart the Syncthing daemon."""
        subprocess.run(
            ['syncthing', 'cli', 'operations', 'restart', '--home', str(self.home_dir)],
            check=True
        )

    def start(self):
        """Start the Syncthing daemon."""
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the Syncthing daemon."""
        if self.thread is not None:
            self.thread.join()
            self.thread = None