# 🛡️ Basic Firewall Using Python

## 📖 Overview
This project is a simple **Python-based firewall** that monitors and filters network traffic based on user-defined rules.
It provides an introductory understanding of how firewalls work at the **network (Layer 3)** and **transport (Layer 4)** levels.
## ⚙️ Features
- Real-time monitoring of incoming and outgoing packets  
- User-defined blocking of IP addresses and ports  
- Logs blocked and allowed packets to the console  
- Built using **Python’s socket** and **Scapy** libraries  
## 🧠 Working Principle
1. The firewall captures network packets using Scapy.  
2. It checks each packet’s:
   - Source and destination **IP address (Layer 3)**
   - Source and destination **port number (Layer 4)**
3. If a packet matches a blocked IP or port, it is marked as **blocked**.  
4. Otherwise, it is **allowed** and displayed on the console.  
## 🧩 Requirements
- Python 3.x  
- Install Scapy library:
  ```bash
  pip install scapy
