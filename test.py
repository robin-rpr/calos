#!/usr/bin/env python3
"""
Test script for Clearstack Daemon
"""

import json
import requests
import time
import sys

# Configuration
DAEMON_URL = "http://localhost:4242"
TEST_IMAGE_PATH = "/tmp/test-image"  # You'll need to create this or use an existing image

def test_health():
    """Test health endpoint"""
    print("Testing health endpoint...")
    try:
        response = requests.get(f"{DAEMON_URL}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_list_containers():
    """Test listing containers"""
    print("Testing list containers...")
    try:
        response = requests.get(f"{DAEMON_URL}/containers")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ List containers passed: {len(data.get('containers', []))} containers")
            return True
        else:
            print(f"❌ List containers failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ List containers failed: {e}")
        return False

def test_start_container(container_id, image_path, command=None):
    """Test starting a container"""
    print(f"Testing start container {container_id}...")
    try:
        payload = {
            "container_id": container_id,
            "image_path": image_path
        }
        if command:
            payload["command"] = command
        
        response = requests.post(
            f"{DAEMON_URL}/containers",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload)
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print(f"✅ Start container passed: PID {data.get('pid')}")
                return True
            else:
                print(f"❌ Start container failed: {data.get('error')}")
                return False
        else:
            print(f"❌ Start container failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Start container failed: {e}")
        return False

def test_get_logs(container_id):
    """Test getting container logs"""
    print(f"Testing get logs for {container_id}...")
    try:
        response = requests.get(f"{DAEMON_URL}/containers/{container_id}/logs")
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                stdout_count = len(data.get("stdout", []))
                stderr_count = len(data.get("stderr", []))
                print(f"✅ Get logs passed: {stdout_count} stdout, {stderr_count} stderr lines")
                return True
            else:
                print(f"❌ Get logs failed: {data.get('error')}")
                return False
        else:
            print(f"❌ Get logs failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Get logs failed: {e}")
        return False

def test_stop_container(container_id):
    """Test stopping a container"""
    print(f"Testing stop container {container_id}...")
    try:
        response = requests.delete(f"{DAEMON_URL}/containers/{container_id}")
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print(f"✅ Stop container passed")
                return True
            else:
                print(f"❌ Stop container failed: {data.get('error')}")
                return False
        else:
            print(f"❌ Stop container failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Stop container failed: {e}")
        return False

def create_test_image():
    """Create a simple test image if it doesn't exist"""
    import os
    if not os.path.exists(TEST_IMAGE_PATH):
        print(f"Creating test image at {TEST_IMAGE_PATH}...")
        os.makedirs(TEST_IMAGE_PATH, exist_ok=True)
        
        # Create a simple bash script
        script_content = """#!/bin/bash
echo "Hello from Clearstack container!"
echo "Container ID: $CONTAINER_ID"
echo "Current directory: $(pwd)"
echo "Environment:"
env | sort
sleep 5
echo "Container finished"
"""
        
        with open(os.path.join(TEST_IMAGE_PATH, "entrypoint.sh"), "w") as f:
            f.write(script_content)
        
        os.chmod(os.path.join(TEST_IMAGE_PATH, "entrypoint.sh"), 0o755)
        print("✅ Test image created")
    else:
        print("✅ Test image already exists")

def main():
    """Main test function"""
    print("Clearstack Daemon Test Suite")
    print("=" * 40)
    
    # Check if daemon is running
    if not test_health():
        print("❌ Daemon is not running. Please start the daemon first.")
        print("Run: systemctl start clearly.service")
        sys.exit(1)
    
    # Create test image
    create_test_image()
    
    # Test basic functionality
    test_list_containers()
    
    # Test container lifecycle
    container_id = "test-container-1"
    
    # Start container
    if test_start_container(container_id, TEST_IMAGE_PATH, ["/bin/bash", "-c", "echo 'Hello World'; sleep 2"]):
        # Wait a bit for container to start
        time.sleep(1)
        
        # Get logs
        test_get_logs(container_id)
        
        # Wait for container to finish
        time.sleep(3)
        
        # Get logs again
        test_get_logs(container_id)
        
        # Stop container
        test_stop_container(container_id)
    
    # Test long-running container
    container_id2 = "test-container-2"
    if test_start_container(container_id2, TEST_IMAGE_PATH, ["/bin/bash", "-c", "while true; do echo 'Running...'; sleep 1; done"]):
        # Wait a bit
        time.sleep(2)
        
        # Get logs
        test_get_logs(container_id2)
        
        # Stop container
        test_stop_container(container_id2)
    
    # Final container list
    test_list_containers()
    
    print("\n" + "=" * 40)
    print("Test suite completed!")

if __name__ == "__main__":
    main()