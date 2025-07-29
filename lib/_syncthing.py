import xml.etree.ElementTree as ET
from pathlib import Path
import multiprocessing
import subprocess
import os
import signal
import time


## Classes ##

class Syncthing:
    def __init__(
        self,
        config_dir=Path.home() / ".config/clearly",
        folder_dir=Path("/srv/clearly"),
    ):
        self.folder_dir = folder_dir
        self.config_dir = config_dir
        self.config_file = self.config_dir / "config.xml"
        self.device_id = None
        self.process = None

        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Create folder directory if it doesn't exist
        self.folder_dir.mkdir(parents=True, exist_ok=True)

        # Ensure config file exists
        self.start()
        self.stop()

        # Modify configuration
        if self.config_file.exists():
            tree = ET.parse(self.config_file)
            root = tree.getroot()
            
            # Retrieve the default folder
            folder = root.find("./folder[@id='default']")
            if folder is not None:

                # Update the folder path
                old_path = folder.get("path")
                folder.set("path", self.folder_dir)

                # Unlink the old folder if it is empty
                if old_path and old_path != str(self.folder_dir):
                    old_path_p = Path(old_path)
                    try:
                        if old_path_p.exists() and old_path_p.is_dir() and not any(old_path_p.iterdir()):
                            old_path_p.rmdir()
                    except Exception:
                        pass

                # Extract our peer's device id
                device = folder.find("device")
                if device is not None:
                    self.device_id = device.get("id")

                # Write the configuration
                tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    def set_ip_address(self, ip):
        tree = ET.parse(self.config_file)
        root = tree.getroot()

        # Find the device that matches our device_id
        device = root.find(f"./device[@id='{self.device_id}']")
        if device is not None:
            # Update the IP address
            address_elem = device.find("./address")
            if address_elem is not None:
                address_elem.text = f"tcp://{ip}:22000"
        
        # Write the changes back to the config file
        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)
        
    def add_peer(self, device_id, ip):
        tree = ET.parse(self.config_dir / "config.xml")
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

        # Link folder to peer
        folder = root.find("./folder[@id='default']")
        ET.SubElement(folder, "device", {"id": device_id})

        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    def remove_peer(self, device_id):
        tree = ET.parse(self.config_file)
        root = tree.getroot()

        # Remove device from root
        for dev in root.findall("device"):
            if dev.attrib.get("id") == device_id:
                root.remove(dev)

        # Unlink folder device
        folder = root.find("./folder[@id='default']")
        if folder is not None:
            for dev in folder.findall("device"):
                if dev.attrib.get("id") == device_id:
                    folder.remove(dev)

        tree.write(self.config_file, encoding="utf-8", xml_declaration=True)

    def start(self):
        if self.process is None:
            self.process = multiprocessing.Process(
                target=lambda: os.execvp("syncthing", ["syncthing", "-home", str(self.config_dir)]),
                daemon=True
            )
            self.process.start()
            time.sleep(2)

    def stop(self):
        if self.process is not None:
            os.kill(self.process.pid, signal.SIGTERM)
            self.process.join()
            self.process = None
