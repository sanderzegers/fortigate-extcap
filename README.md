# Wireshark Extcap extension for Fortigate

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

## Description

This Wireshark Extcap plugin enables real-time packet capture directly from FortiGate devices, streamlining network troubleshooting. It supports defining capture filters within Wireshark and allows multiple parallel capture sessions for enhanced flexibility and analysis.

Extcap plugins extend Wireshark’s capture capabilities by allowing it to collect packets from external sources, such as remote devices or specialized hardware, instead of just local network interfaces. This makes it possible to capture traffic from FortiGate firewalls directly within Wireshark, without needing additional tools or manual exports.

![Wireshark Screenshot](images/wireshark-extcap.png)

## Features

- Capture packets live into Wireshark
- SSH password or SSH key authentication
- Parallel capture session
- Fortigate VDOM Support
- Simple installation

## Limitations
- Capture speed is limited to about 10 packets per second, so the tcpdump filter must be set accordingly.

## Installation

1. Download the Latest Version
 - Visit the [Releases](https://github.com/sanderzegers/fortigate-extcap/releases/) page and download the version that matches your platform.

2. Locate the Personal Extcap Folder
 - Open Wireshark.
 - Navigate to Help → About Wireshark → Folders → Personal Extcap Path.
 - Click the Location to open the Extcap folder.

3. Copy the binary to excapt folder
 - From the downloaded release, copy the fortigate-extcap.exe (or the appropriate file for your platform) into the "Personal Extcap Path" directory.

4. Restart Wireshark
 - Restart Wireshark to load the custom extcap extension.

## Known limitations

This extcap is still under development. Currently it's in an early beta stage.

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).
