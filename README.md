# Wireshark Extcap extension for Fortigate

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

## Description

This Wireshark Extcap extension enables the capture of live network packets directly from Fortigate devices, supporting multiple Virtual Domains (VDOMs). It is designed to integrate with Wireshark, providing a straightforward solution for network administrators and security professionals to monitor and troubleshoot their networks.

![Wireshark Screenshot](images/wireshark-extcap.png)

## Features

- Capture packets live to Wireshark
- Fortigate VDOM Support
- Simple installation

## Installation

1. Launch Wireshark.
2. Go to "Help" -> "About Wireshark" -> "Folders" -> "Personal Extcap Path".
3. Copy the `fortidump.exe` file from this repository into the "Personal Extcap Path" folder.
4. Restart Wireshark to enable the custom extcap extension.

## Known limitations

This extcap is still under development. Currently it's in an early alpha stage.

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).
