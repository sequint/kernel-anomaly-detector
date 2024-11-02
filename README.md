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
   sudo apt install linux-headers-$(uname -r)
   sudo apt install make
   ```

If using VSCode, intellisense may produce red underline errors in the #inlude statements.
Below are steps to remedy:

1. In VSCode type Ctrl/Shift/P
2. In the search bar search for 'C/C++: Edit Configurations (UI)'
3. Click on 'c_cpp_properties.json' on the left hand side
4. Edit indludePath to have the following paths (replace (uname -r) with system uname, can be found by type 'uname -r' into the terminal):

            "includePath": [
                "${workspaceFolder}/**",
                "/usr/src/linux-headers-(uname -r)/include",
                "/usr/src/linux-headers-(uname -r)/include/uapi",
                "/usr/src/linux-headers-(uname -r)/arch/x86/include",
                "/usr/include",
                "/usr/src/linux-headers-(uname -r)/arch/x86/include/generated"
            ]

If the red lines still appear, they should be fixed after a succesful build.

## Build

```bash
# Navigate to the directory you cloned the module into
cd ~/module_dir_path

# Compile the kernel module
make

# Load module (insure the ko file was generated after the make build first)
sudo insmod kernel_module.ko

# Check last log to see if the module loaded
sudo dmesg | tail -1

# Unload module
sudo rmmod kernel_module

# Check last log to ensure the module unloaded
sudo dmesg | tail -1
```

## Roadmap

This will serve as a static guide of the project roadmap.  GitHub issues will be created to manage each milestone.

1. Set Up the Development Environment and Kernel Module Skeleton
2. Implement Process Monitoring
3. Add Anomaly Detection Logic (Using dynamic historical statistics)
4. Improve Logging and Report Generation
5. Testing and Threshold Adjustment

### Time Permitted Kernel-ml integration

1. Set Up Basic Machine Learning Model in User Space (C++/Rust/Python)
2. Integrate User Space Model with Monitoring as a second level
3. Set Up Kernel-ML model in Kernel Space (Experimental)
4. Integrate first level anomoly detection, to kernel-ml, to user space model
5. Extensive Testing and ML Benchmarking

## Authors

- [Steven Quintana](https://github.com/sequint)
- Mason Wilson IV