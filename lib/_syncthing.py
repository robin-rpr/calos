import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import threading
import requests
import hashlib
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
        self.config_sha256 = None
        self.home_dir = home_dir
        self.process = None
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
        
        self._indent_xml(root)
        self._write_config(tree)
        
    def add_peer(self, device_id, ip, name):
        """Add a peer to the Syncthing configuration."""
        tree = ET.parse(self.config_file)
        root = tree.getroot()
        
        # Remove existing device if present (replace behavior)
        for existing_device in root.findall("device"):
            if existing_device.attrib.get("id") == device_id:
                root.remove(existing_device)
        
        # Also remove from all folders
        for folder in root.findall("folder"):
            for device_ref in folder.findall("device"):
                if device_ref.attrib.get("id") == device_id:
                    folder.remove(device_ref)

        # Copy default device configuration
        defaults = root.find("./defaults")
        default_device = defaults.find("./device")
        device = copy.deepcopy(default_device)
        
        # Override with specific values
        device.set("id", device_id)
        device.set("name", name)
        
        # Update the address element with the specific IP
        address_elem = device.find("./address")
        if address_elem is not None:
            address_elem.text = f"tcp://{ip}:22000"

        # Find the correct position to insert the device (after options, before defaults)
        options_elem = root.find("./options")
        if options_elem is not None:
            # Insert after options element
            options_index = list(root).index(options_elem)
            root.insert(options_index + 1, device)
        else:
            # Insert before defaults element
            defaults_elem = root.find("./defaults")
            if defaults_elem is not None:
                defaults_index = list(root).index(defaults_elem)
                root.insert(defaults_index, device)
            else:
                # Fallback: append to root
                root.append(device)

        # Link device to all folders
        for folder in root.findall("folder"):
            ET.SubElement(folder, "device", {"id": device_id})

        self._indent_xml(root)
        self._write_config(tree)

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

        self._indent_xml(root)
        self._write_config(tree)

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

        self._indent_xml(root)
        self._write_config(tree)

    def remove_folder(self, id):
        """Remove a folder from the Syncthing configuration."""
        tree = ET.parse(self.config_file)
        root = tree.getroot()

        # Remove the folder
        for folder in root.findall("folder"):
            if folder.attrib.get("id") == id:
                root.remove(folder)

        self._indent_xml(root)
        self._write_config(tree)

    @property
    def device_id(self):
        """Get the device ID of the Syncthing device."""
        return subprocess.check_output(['syncthing', '--device-id', '--home',
                                        str(self.home_dir)]).decode('utf-8').strip()

    @property
    def needs_restart(self):
        """Check if the Syncthing configuration has changed."""
        return self.config_sha256 != hashlib.sha256(self.config_file.read_bytes()).hexdigest()

    def _indent_xml(self, elem, level=0):
        """Add pretty-printing indentation to XML elements."""
        i = "\n" + level * "    "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "    "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                self._indent_xml(elem, level + 1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i

    def _write_config(self, tree):
        """Write the Syncthing configuration to the file."""
        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)
        self.config_sha256 = hashlib.sha256(self.config_file.read_bytes()).hexdigest()

    def serve_forever(self):
        """Start the Syncthing daemon."""
        self.process = subprocess.Popen(
            ['syncthing', 'serve', '--home', str(self.home_dir)]
        )
        self.process.wait()

    def start(self):
        """Start the Syncthing daemon."""
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the Syncthing daemon."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()
            self.process = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=10)
            self.thread = None