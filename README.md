# Kernel Anamoly Detector

![License](https://img.shields.io/badge/license-MIT-brightgreen)
![Issues](https://img.shields.io/github/issues/sequint/kernel-anomaly-detector)
![Version](https://img.shields.io/badge/version-2.2.0-blue)
![Platform](https://img.shields.io/badge/platform-Linux-magenta)
![Kernel Development](https://img.shields.io/badge/Kernel%20Development-Linux%20Kernel-magenta)

## Table of Contents

- [About](#About)
- [Installation](#installation)
- [Build and Run](#build-and-run)
- [Sysfs Interface](#sysfs-interface-runtime-threshold-updates)
- [Future Integrations](#future-integrations)

## About

A Linux kernel module for real-time anomaly detection of processes. The module monitors CPU time, memory usage, and network send/receive bandwidth for all running processes and flags anomalies when configurable thresholds are exceeded.

Key features:
- Dynamic thresholds: thresholds update automatically based on historical averages.
- Manual override: administrators can update thresholds at runtime via sysfs.
- Threaded monitoring: lightweight kernel thread checks every 30 seconds.
- Structured logging: anomalies are timestamped and logged to dmesg.

This project demonstrates system-level programming, concurrency control (mutex, RCU), and integration of monitoring directly in the Linux kernel.

## Installation

*Note: These instructions assume you’re running on a Linux system with kernel headers installed.*

1. Clone repo into a local project directory
2. Open a bash terminal and follow the following commands to install linux headers:
   ```bash
   sudo apt update
   sudo apt install gcc make linux-headers-$(uname -r)
   ```

### VSCode c_cpp properties

c_cpp_properties.json file has been included for use in VSCode IDE.  If you are not using Code for development, delete this directory.
If using Code, in a Bash shell enter the command 'uname -r' after installing the above packages.
Copy the result and replace the <uname -r> portions of the json file with the value.

## Build and Run

```bash
# Navigate to the directory you cloned the module into
cd ~/module_dir_path

# Compile the kernel module
make

# If running on Safe Mode in a Linux OS, create a kernel key, then sign it using the below script
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
  ~/kernel-keys/MOK.priv ~/kernel-keys/MOK.der kernel_module.ko


# Load module (insure the ko file was generated after the make build first)
sudo insmod kernel_module.ko

# Check to see if the module loaded
lsmod | grep kernel_module

# Open and view the anomaly logs in real time
sudo dmesg -w | grep "ANOMALY MONITOR"

# Unload the module
sudo rmmod kernel_module

# Confirm that the module was removed
sudo dmesg | tail -1
lsmod | grep kernel_module

# Clear make files (optional)
make clean
```

## Sysfs Interface (runtime threshold updates)

Once the module is loaded, you can update thresholds at runtime:

```bash
# Update thresholds: CPU MEM SEND RECV
echo "90 200000 15 60" | sudo tee /sys/anomaly_module/thresholds

# Reset thresholds back to automatic (adaptive) mode
echo 1 | sudo tee /sys/anomaly_module/reset_thresholds
```

## Future Integrations

1. Add persistent logging to /var/log/anomaly_monitor.log.
2. Explore fault-tolerance mechanisms for noisy or unreliable environments.
3. Extend module for domain-specific use cases (e.g., critical infrastructure, embedded radiation monitoring).