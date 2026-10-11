# Network Analysis & Telemetry Dashboard
I have been exploring networking for a while now and today I decided to build a simple project to analyse the logs from wireshark. Details are listed below:

A full-stack web application built with Python, Flask, and Scapy for parsing network packet captures (.pcap) and visualizing network traffic patterns.

## Features
* **Packet Parsing:** Uses Scapy to ingest and parse Layer 2 and Layer 3 frames.
* **Protocol Distribution:** Identifies and tallies TCP, UDP, ARP, and other protocols.
* **Device Communication Tracking:** Maps Source IP to Destination IP to visualize top network talkers.
* **Interactive Dashboard:** Uses Chart.js and Tailwind CSS for real-time traffic visualization.

## Tech Stack
* **Backend:** Python, Flask, Scapy
* **Frontend:** HTML, Tailwind CSS, Chart.js
