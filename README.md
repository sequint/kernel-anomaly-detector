# Kernel Anamoly Detector

![License](https://img.shields.io/badge/license-MIT-brightgreen)
![Issues](https://img.shields.io/github/issues/sequint/kernel-anomaly-detector)
![Contributors](https://img.shields.io/github/contributors/sequint/kernel-anomaly-detector)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Platform](https://img.shields.io/badge/platform-Linux-brightgreen)
![Kernel Development](https://img.shields.io/badge/Kernel%20Development-Linux%20Kernel-brightgreen)

## Table of Contents

- [About](#About)
- [Installation](#Installation)
- [Build](#Build)
- [Roadmap](#Roadmap)
- [Authors](#Authors)

## About

A kernel module for monitoring system processes and detecting anomalies as potential malware threats based on CPU and memory usage.

## Installation

*Note: Installation instructions to be updated as progress is made on the project*

1. Clone repo into a local project directory
2. Open a bash terminal and follow the following commands to install linux headers:
   ```bash
   sudo apt update
   sudo apt install gcc
   sudo apt install linux-headers-$(uname -r)
   sudo apt install make
   ```

### VSCode c_cpp properties

c_cpp_properties.json file has been included for use in VSCode IDE.  If you are not using Code for development, delete this directory.
If using Code, in a Bash shell enter the command 'uname -r' after installing the above packages.
Copy the result and replace the (uname -r) portions of the json file with the value.

## Build

```bash
# Navigate to the directory you cloned the module into
cd ~/module_dir_path

# Compile the kernel module
make

# Load module (insure the ko file was generated after the make build first)
sudo insmod kernel_module.ko

# Check to see if the module loaded
lsmod | grep kernel_module

# Open and view module logs in real time
sudo dmesg -w | grep "ANOMALY MONITOR"

# Open and view logs written to log file in terminal or in VS Code
cat /var/log/anomaly_monitor.log
code /var/log/anomaly_monitor.log

# Unload module (will up to 30 seconds to unload)
sudo rmmod kernel_module

# Check last log to ensure the module unloaded
sudo dmesg | tail -1
lsmod | grep kernel_module
```

## Roadmap

This will serve as a static guide of the project roadmap.  GitHub issues will be created to manage each milestone.

1. ~~Set Up the Development Environment and Kernel Module Skeleton~~
2. ~~Implement Process Monitoring~~
3. ~~Add Anomaly Detection Logic (Using dynamic historical statistics)~~
4. ~~Improve Logging and Report Generation~~
5. ~~Testing and Threshold Adjustment~~

### Time Permitted Kernel-ml integration

1. ~~Set Up Basic Machine Learning Model in User Space (C++/Rust/Python)~~
2. Integrate User Space Model with Monitoring as a second level
3. Set Up Kernel-ML model in Kernel Space (Experimental)
4. Integrate first level anomoly detection, to kernel-ml, to user space model
5. Extensive Testing and ML Benchmarking

## Authors

- [Steven Quintana](https://github.com/sequint)
- Mason Wilson IV