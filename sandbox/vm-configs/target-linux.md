# Virtual Machine Specification: Target Linux Endpoint (Ubuntu 22.04)

This specification defines the configuration for the optional secondary Linux victim virtual machine used for evaluating Linux-specific fileless techniques (LOLBins abuse, memory-only execution, and auditd forensics).

---

## 1. System Specifications

- **Role**: Secondary victim endpoint for Linux memory forensics and shell telemetry.
- **Operating System**: Ubuntu 22.04 LTS (x64).
- **vCPU Allocation**: 2 vCPUs.
- **Memory Allocation**: 4 GB RAM.
- **Virtual Disk**: 40 GB.
- **Hypervisor**: VMware Workstation Pro / Player, VirtualBox, or Hyper-V.

---

## 2. Network Configuration

- **Network Adapter**: 1 virtual network adapter.
- **Connection Type**: **Host-Only / Custom Internal Virtual Network** (strictly internal to host).
- **PROHIBITION**: Bridged and NAT adapters are **strictly forbidden**.
- **IP Addressing**: Static IPv4.
  - **IP Address**: `192.168.100.30`
  - **Subnet Mask**: `255.255.255.0` (`/24`)
  - **Default Gateway**: None.
  - **DNS**: None.

```text
# /etc/netplan/01-netcfg.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.100.30/24
```

---

## 3. Hypervisor Isolation & Hardening

Explicitly disabled:
- **Shared Folders**: Disabled.
- **Bidirectional Clipboard**: Disabled.
- **Drag and Drop**: Disabled.
- **Host Time Synchronization**: Enabled for timeline correlation with the Attacker VM and host logs.

---

## 4. Forensic Telemetry & Acquisition Setup

### 4.1 Linux Audit Subsystem (`auditd`)
Configure `auditd` rules to monitor process creation and socket connections:
```text
# /etc/audit/rules.d/malware_audit.rules
-a always,exit -F arch=b64 -S execve -k process_exec
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S memfd_create -k memory_exec
```

### 4.2 Volatile Memory Tooling (LiME)
Install kernel headers and build the LiME kernel module:
```bash
sudo apt-get update && sudo apt-get install -y build-essential linux-headers-$(uname -r) git
git clone https://github.com/504ensicsLabs/LiME.git /opt/LiME
cd /opt/LiME/src && make
# Produces lime-$(uname -r).ko for volatile acquisition during execution
```

---

## 5. Baseline Snapshot

1. Flush bash history, temporary files, and audit logs:
   ```bash
   sudo rm -rf /var/log/audit/audit.log*
   history -c
   ```
2. Power off the VM and capture snapshot: `Linux_Clean_Baseline_v1`.
3. Revert to `Linux_Clean_Baseline_v1` immediately following any execution.
