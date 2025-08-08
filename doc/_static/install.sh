#!/bin/bash
#
# This script detects the current RPM-based Linux distribution and
# installs the 'clearly' package from the Gemfury repository.
# curl -fsSL https://clearly.run/install.sh | sh

# Exit immediately if a command fails (-e) or if an unset variable is used (-u).
set -eu

# All code is wrapped in a main() function to prevent a partial download
# from executing incomplete commands.
main() {
	#
	# Step 1: Detect OS and package manager
	#
	# We use /etc/os-release to identify the distribution and determine whether
	# to use 'dnf' (modern) or 'yum' (legacy).
	#
	OS=""
	PACKAGEMANAGER=""

	if [ -f /etc/os-release ]; then
		# Source the os-release file to get variables like ID and VERSION_ID
		. /etc/os-release
		case "$ID" in
			rhel|centos|fedora|rocky|almalinux|amzn|ol)
				# Use PRETTY_NAME for user-friendly output
				OS="$PRETTY_NAME"
				# Use 'yum' for older systems like CentOS 7 and Amazon Linux 2
				if ([ "$ID" = "centos" ] && [ "${VERSION_ID%%.*}" = "7" ]) || [ "$ID" = "amzn" ]; then
					PACKAGEMANAGER="yum"
				else
					PACKAGEMANAGER="dnf"
				fi
				;;
		esac
	fi

	# If we couldn't identify the OS as a supported RPM-based system, exit.
	if [ -z "$PACKAGEMANAGER" ]; then
		echo
		if [ -n "${ID:-}" ]; then
			echo "Clearly is not supported on your system."
		else
			echo "Could not determine your operating system."
		fi
		echo "For more information, see https://clearly.run/install"
		exit 1
	fi

	#
	# Step 2: Check for necessary privileges
	#
	SUDO=""
	if [ "$(id -u)" -ne 0 ]; then
		# If not running as root, check for 'sudo' or 'doas'.
		if command -v sudo >/dev/null; then
			SUDO="sudo"
		elif command -v doas >/dev/null; then
			SUDO="doas"
		else
			echo "This script needs to run as root."
			echo "Please re-run with 'sudo' or 'doas'."
			exit 1
		fi
	fi

	#
	# Step 3: Apply system configuration
	#
	set +e # Temporarily disable exit-on-error for this check
	echo "1" | $SUDO tee /proc/sys/net/ipv4/ip_forward > /dev/null
	RC=$?
	set -e # Re-enable exit-on-error
	if [ $RC -eq 0 ]; then
		echo "IP forwarding enabled."
	else
		echo "Warning: Could not enable IP forwarding automatically." >&2
		echo "You may need to run the following command as root:" >&2
		echo "  echo 1 > /proc/sys/net/ipv4/ip_forward" >&2
	fi

	#
	# Step 4: Enable the additional repositories
	#
	case "$VERSION_ID" in
		"8")
			dnf config-manager --set-enabled ha
			dnf config-manager --set-enabled rs
			;;
		"9")
			dnf config-manager --set-enabled highavailability
			dnf config-manager --set-enabled resilientstorage
			;;
		*)
			echo "Warning: Could not enable additional repositories automatically." >&2
			echo "You may need to run the following commands as root:" >&2
			echo "  dnf config-manager --set-enabled highavailability" >&2
			echo "  dnf config-manager --set-enabled resilientstorage" >&2
			;;
	esac

	#
	# Step 5: Install the 'clearly' package
	#

	# The URL of our Gemfury RPM repository.
	REPO_URL="https://repo.clearly.run/yum"

	# The configuration for the .repo file.
	# It's safer to create this file than to use a config-manager command,
	# as it avoids installing extra dependencies ('yum-utils' or 'dnf-plugins-core').
	REPO_CONFIG="[clearly]
name=Clearly Repository
baseurl=$REPO_URL
enabled=1
gpgcheck=0"

	# Use 'set -x' to print the commands being executed for transparency.
	set -x

	# Add the 'clearly' repository configuration to the system.
	echo "$REPO_CONFIG" | $SUDO tee /etc/yum.repos.d/clearly.repo > /dev/null

	# Install the package using the detected package manager.
	# The '-y' flag automatically answers 'yes' to any prompts.
	$SUDO $PACKAGEMANAGER install -y clearly

	# Stop printing executed commands.
	set +x

	echo
	echo "Installation complete."
}

# Execute the main function.
main