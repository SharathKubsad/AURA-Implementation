# Isolated Network Architecture & Design (Task A1)

This document defines the network topology, IP addressing plan, and isolation safeguards governing the malware analysis sandbox environment.

---

## 1. Network Topology

The sandbox uses a **two-role virtual topology** residing on an entirely self-contained virtual switch (Host-Only / Internal Network).

```
                      +-----------------------------------------+
                      |         HOST PHYSICAL HARDWARE          |
                      | (Host OS, Physical NIC, Home/Office LAN)|
                      +-----------------------------------------+
                                           X
                                 [ STRICT AIR GAP ]
                                (No Routing / No NAT)
                                           X
    ========================== ISOLATED VIRTUAL SWITCH ==========================
                     Subnet: 192.168.100.0/24 (RFC 1918)
                        No Internet / No Default Gateway
    =============================================================================
             |                                    |
             |                                    |
    +------------------+                 +------------------+
    |   ATTACKER VM    |                 |    TARGET VM     |
    |   (Kali Linux)   |                 | (Windows 10/11)  |
    |  192.168.100.10  |                 |  192.168.100.20  |
    +------------------+                 +------------------+
             |                                    |
             +----------- C2 Beaconing / ---------+
                          Reverse Shell Traffic
```

---

## 2. IP Addressing Plan (RFC 1918)

| Endpoint | Interface | IP Address | Subnet Mask | Gateway | DNS |
|---|---|---|---|---|---|
| **Subnet Network** | N/A | `192.168.100.0` | `255.255.255.0` (`/24`) | None | None |
| **Attacker VM** | `eth0` | `192.168.100.10` | `255.255.255.0` | None | None / Local |
| **Target Windows VM**| `Ethernet0` | `192.168.100.20` | `255.255.255.0` | None | None |
| **Target Linux VM** | `ens33` | `192.168.100.30` | `255.255.255.0` | None | None |
| **Broadcast** | N/A | `192.168.100.255`| `255.255.255.0` | None | None |

### Static IP Addressing vs. DHCP
All endpoints use **static IP assignments**. The virtual switch's built-in DHCP server is disabled to:
1. Prevent unintended IP reassignments across snapshot restores.
2. Eliminate rogue DHCP broadcast noise from forensic packet captures.
3. Guarantee deterministic addressing for automated feature extraction scripts.

---

## 3. Why NAT and Bridged Modes Are Strictly Prohibited

### Bridged Networking Risks
- In Bridged mode, the virtual machine shares the physical network adapter and receives an IP address directly from the physical LAN.
- **Catastrophic Risk**: A malicious payload or wormable exploit running on the target VM can directly scan, attack, and compromise real devices on your physical home or organizational network.

### NAT (Network Address Translation) Risks
- In NAT mode, the hypervisor acts as a router translating guest traffic to the host's physical IP address, giving the guest outbound Internet access.
- **Risks**:
  1. Active malware can communicate with real, external threat-actor Command & Control (C2) servers, leading to secondary payload drops or DDoS participation.
  2. Outbound malicious traffic originating from your institutional/home IP address triggers abuse alerts, ISP disconnection, or legal liabilities.
  3. External C2 servers may be taken down or sinkholed, corrupting dataset repeatability and timing metrics.

### Host-Only / Internal Network Guarantee
Host-Only / Internal virtual networking isolates all traffic strictly to the virtual switch running inside hypervisor memory. Frames cannot traverse the physical NIC to the local network or the Internet.

---

## 4. Packet Capture Architecture

To support the **Network Modality** (Track B LightGBM model and feature extraction):
1. **Virtual Interface Sniffing**: `tshark` or `scapy` is attached directly to the host-only virtual adapter (e.g., `VMnet2` on Windows host or virtual tap interface on Linux).
2. **Promiscuous Mode**: The capture tool observes all unicast packets exchanged between the Attacker VM (`192.168.100.10`) and Target VM (`192.168.100.20`).
3. **Capture Outputs**:
   - Packets are streamed into a raw capture file named `<sample_id>_network.pcap` in the designated external evidence directory.
   - Timestamps and packet inter-arrival times are extracted to compute the `beacon_regularity_score` and bandwidth metrics.

---

## 5. Pre-Execution Isolation Checklist

Before initiating any sample execution, the operator must verify:
- [ ] Hypervisor network adapter is confirmed as **Host-Only** or **Internal Network**.
- [ ] No secondary network adapters (NAT, Bridged, Host-Interface) are connected.
- [ ] `ping 8.8.8.8` or any external address from inside the guest fails with *Destination Host Unreachable*.
- [ ] `ping 192.168.100.10` between target and attacker succeeds.
