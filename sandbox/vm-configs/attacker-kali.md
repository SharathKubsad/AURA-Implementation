# Virtual Machine Specification: Attacker / C2 (Kali Linux)

This specification defines the configuration for the Attacker/C2 virtual machine used in the isolated sandbox.

---

## 1. System Specifications

- **Role**: Command & Control (C2) endpoint, beacon receiver, and network listener.
- **Operating System**: Kali Linux 2024.x (64-bit).
- **vCPU Allocation**: 4 vCPUs.
- **Memory Allocation**: 8 GB RAM.
- **Virtual Disk**: 60 GB (dynamically allocated, NVMe/SCSI virtual controller).
- **Hypervisor Compatibility**: VMware Workstation Pro / Player, VirtualBox, or Hyper-V.

---

## 2. Network Configuration

- **Network Adapter**: 1 virtual network adapter.
- **Connection Type**: **Host-Only / Custom Internal Virtual Network** (e.g., `VMnet2` or `intnet`).
- **PROHIBITION**: Bridged and NAT adapters are **strictly forbidden**.
- **IP Addressing**: Static IPv4.
  - **IP Address**: `192.168.100.10`
  - **Subnet Mask**: `255.255.255.0` (`/24`)
  - **Default Gateway**: None (no routing beyond the isolated virtual switch).
  - **DNS**: None or local dummy responder.

### Network Interface Configuration (`/etc/network/interfaces`)
```text
auto eth0
iface eth0 inet static
    address 192.168.100.10
    netmask 255.255.255.0
```

---

## 3. Hypervisor Isolation & Hardening

The following hypervisor features must be explicitly disabled in VM settings:
- **Shared Folders**: Disabled.
- **Bidirectional Clipboard**: Disabled.
- **Drag and Drop**: Disabled.
- **USB Device Auto-Connect**: Disabled.

---

## 4. Tooling Preparation (Infrastructure Only)

> [!IMPORTANT]
> **Task A1 Constraint**: In Task A1, offensive frameworks (Metasploit, Empire, Cobalt Strike, etc.) are **not** installed, configured, or executed. This document only defines the infrastructure baseline.
>
> During subsequent Phase 1 data collection:
> - The Attacker VM will host publicly documented security testing frameworks (such as Metasploit or Empire) to launch standard techniques against the Target VM over the host-only network.
> - Network traffic capture tools (`tshark`, `tcpdump`) will run on this interface to verify beaconing traffic generated during executions.

---

## 5. Maintenance & Baseline

- Once installed and updated via a temporary secure staging network, disconnect all external interfaces and lock the adapter to Host-Only before taking the clean snapshot `Kali_Baseline_v1`.
