#!/usr/bin/env python3

import argparse
import json
import os.path
import sys
import yaml
import requests

try:
    # Cython provides PKGLIBDIR.
    sys.path.insert(0, PKGLIBDIR)
except NameError:
    # Extend sys.path to include the parent directory. This is necessary because this
    # script resides in a subdirectory, and we need to import shared modules located
    # in the project's top-level 'lib' directory.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

import _clearly as _clearly
import _filesystem as _filesystem
import _misc as _misc


## Constants ##

# Default daemon URL
DEFAULT_DAEMON_URL = "http://localhost:8080"


## Classes ##

class ComposeDeployer:
    """Deployer for docker-compose.yml files"""
    
    def __init__(self, daemon_url=DEFAULT_DAEMON_URL):
        self.daemon_url = daemon_url
        self.session = requests.Session()
    
    def parse_compose_file(self, compose_file):
        """Parse docker-compose.yml file"""
        try:
            with open(compose_file, 'r') as f:
                compose_data = yaml.safe_load(f)
            
            if not compose_data or 'services' not in compose_data:
                _clearly.FATAL("Invalid docker-compose.yml: no services defined")
            
            return compose_data
        except yaml.YAMLError as e:
            _clearly.FATAL(f"Error parsing docker-compose.yml: {e}")
        except FileNotFoundError:
            _clearly.FATAL(f"Compose file not found: {compose_file}")
    
    def deploy_service(self, service_name, service_config):
        """Deploy a single service"""
        try:
            # Extract service configuration
            image = service_config.get('image')
            if not image:
                _clearly.FATAL(f"Service '{service_name}' has no image specified")
            
            # Build command
            command = []
            if 'command' in service_config:
                if isinstance(service_config['command'], list):
                    command = service_config['command']
                else:
                    command = [service_config['command']]
            
            # Build environment variables
            environment = {}
            if 'environment' in service_config:
                if isinstance(service_config['environment'], dict):
                    environment = service_config['environment']
                elif isinstance(service_config['environment'], list):
                    for env_var in service_config['environment']:
                        if '=' in env_var:
                            key, value = env_var.split('=', 1)
                            environment[key] = value
            
            # Build port mappings
            publish = {}
            if 'ports' in service_config:
                for port_mapping in service_config['ports']:
                    if isinstance(port_mapping, str):
                        # Format: "8080:80" or "8080"
                        if ':' in port_mapping:
                            host_port, container_port = port_mapping.split(':', 1)
                            publish[host_port] = container_port
                        else:
                            # Just host port, use same for container
                            publish[port_mapping] = port_mapping
                    elif isinstance(port_mapping, dict):
                        # Format: {"target": 80, "published": 8080}
                        target = str(port_mapping.get('target', ''))
                        published = str(port_mapping.get('published', ''))
                        if target and published:
                            publish[published] = target
            
            # Prepare request payload
            payload = {
                'id': service_name,
                'image': image,
                'command': command,
                'publish': publish,
                'environment': environment
            }
            
            _clearly.INFO(f"Deploying service '{service_name}' with image '{image}'")
            
            # Make REST API call to daemon
            response = self.session.post(
                f"{self.daemon_url}/api/containers",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'success' in result and result['success']:
                    _clearly.INFO(f"Successfully deployed service '{service_name}'")
                    return result
                else:
                    error_msg = result.get('error', 'Unknown error')
                    _clearly.ERROR(f"Failed to deploy service '{service_name}': {error_msg}")
                    return None
            else:
                _clearly.ERROR(f"HTTP error {response.status_code} deploying service '{service_name}'")
                return None
                
        except requests.exceptions.RequestException as e:
            _clearly.ERROR(f"Network error deploying service '{service_name}': {e}")
            return None
        except Exception as e:
            _clearly.ERROR(f"Unexpected error deploying service '{service_name}': {e}")
            return None
    
    def deploy_stack(self, compose_file, stack_name=None):
        """Deploy all services from docker-compose.yml"""
        # Parse compose file
        compose_data = self.parse_compose_file(compose_file)
        
        # Use stack name from compose file or default
        if not stack_name:
            stack_name = compose_data.get('name', 'default')
        
        _clearly.INFO(f"Deploying stack '{stack_name}' from {compose_file}")
        
        # Deploy each service
        deployed_services = []
        failed_services = []
        
        for service_name, service_config in compose_data['services'].items():
            result = self.deploy_service(service_name, service_config)
            if result:
                deployed_services.append(service_name)
            else:
                failed_services.append(service_name)
        
        # Report results
        if deployed_services:
            _clearly.INFO(f"Successfully deployed {len(deployed_services)} services: {', '.join(deployed_services)}")
        
        if failed_services:
            _clearly.ERROR(f"Failed to deploy {len(failed_services)} services: {', '.join(failed_services)}")
            return False
        
        return True


## Main ##

def main():
    ap = _clearly.ArgumentParser(
        description="Deploy services from docker-compose.yml file",
        epilog="Deploys services to the Clearly daemon via REST API",
        sub_title="subcommands",
        sub_metavar="CMD")
    
    # Common options
    common_opts = {
        (None, "deploy options"): [
            [["--daemon-url"],
             {"metavar": "URL",
              "default": DEFAULT_DAEMON_URL,
              "help": f"daemon URL (default: {DEFAULT_DAEMON_URL})"}],
            [["--stack-name"],
             {"metavar": "NAME",
              "help": "stack name (default: from compose file or 'default')"}],
            [["-v", "--verbose"],
             {"action": "count",
              "default": 0,
              "help": "print extra chatter (can be repeated)"}],
            [["--debug"],
             {"action": "store_true",
              "help": "add short traceback to fatal error hints"}],
            [["--dependencies"],
             {"action": "_misc.Dependencies",
              "help": "print any missing dependencies and exit"}]
        ]
    }
    
    # Helper function to set up a subparser
    def add_opts(p, dispatch, *, deps_check, help_=False):
        if dispatch is not None:
            p.set_defaults(func=dispatch)
        for ((name, title), group) in common_opts.items():
            if name is None:
                p2 = p.add_argument_group(title=title)
            else:
                p2 = p.add_mutually_exclusive_group()
            for (args, kwargs) in group:
                if help_:
                    kwargs2 = kwargs
                else:
                    kwargs2 = {**kwargs, "default": argparse.SUPPRESS}
                p2.add_argument(*args, **kwargs2)
    
    # Main parser
    add_opts(ap, None, deps_check=False, help_=True)
    
    # deploy subcommand
    sp = ap.add_parser("deploy", "deploy services from docker-compose.yml")
    add_opts(sp, deploy_stack, deps_check=True)
    sp.add_argument("compose_file", metavar="COMPOSE_FILE",
                   help="docker-compose.yml file to deploy")
    
    # Parse arguments
    if len(sys.argv) < 2:
        ap.print_help(file=sys.stderr)
        _clearly.exit(1)
    
    cli = ap.parse_args()
    
    # Initialize
    _clearly.init(cli)
    if hasattr(cli, 'func') and cli.func == deploy_stack:
        _clearly.dependencies_check()
    
    # Dispatch
    _clearly.profile_start()
    if hasattr(cli, 'func'):
        cli.func(cli)
    _clearly.warnings_dump()
    _clearly.exit(0)


def deploy_stack(cli):
    """Deploy stack from docker-compose.yml"""
    deployer = ComposeDeployer(cli.daemon_url)
    success = deployer.deploy_stack(cli.compose_file, cli.stack_name)
    
    if not success:
        _clearly.exit(1)


## Bootstrap ##

if __name__ == "__main__":
    try:
        main()
    except _clearly.Fatal_Error:
        _clearly.warnings_dump()
        _clearly.exit(1)
    except KeyboardInterrupt:
        _clearly.exit(1)
