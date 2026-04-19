# Wireshark Extcap extension for Fortigate

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

## Description

With this Wireshark Extcap plugin, you can capture traffic from FortiGate firewalls directly in Wireshark — no extra tools or manual exports needed.

![Wireshark Screenshot](images/wireshark-extcap.png)

## Features

- Capture & stream packets directly from the FortiGate into Wireshark in PCAPng format
- Per-packet interface name and traffic direction (inbound/outbound) visible in Wireshark
- Automatic SSH session exclusion from capture
- SSH agent and password authentication
- Run multiple live capture sessions simultaneously
- Automatic multi-VDOM detection and support
- Configurable packet count limit
- Easy installation
  
## Installation

1. Download the Latest Version
 - Visit the [Releases](https://github.com/sanderzegers/fortigate-extcap/releases/) page and download the version that matches your platform.

2. Locate the Personal Extcap Folder
 - Open Wireshark.
 - Navigate to Help → About Wireshark → Folders → Personal Extcap Path.
 - Click the Location to open the Extcap folder.

3. Copy the binary to the Extcap folder
 - From the downloaded release, copy the fortigate-extcap.exe (or the appropriate file for your platform) into the "Personal Extcap Path" directory.

4. Restart Wireshark
 - Restart Wireshark to load the custom Extcap extension.

## Usage

Once installed, the plugin appears in Wireshark's capture options as **Fortigate Remote Capture (SSH): fortidump**. Click the gear icon to enter the FortiGate address, credentials, and capture settings, then double-click the interface to start capturing.

For detailed configuration, authentication setup, and troubleshooting, see the [Help Documentation](docs/index.md).

## Building from Source

To build the binary on your local machine, make sure Go and Git are installed. 
You can find the plugin folder location in the installation instructions.

Prerequisites: go and git
```bash
apt install git golang-go
```

```bash
git clone https://github.com/sanderzegers/fortigate-extcap.git
cd fortigate-extcap
make build
mkdir -p $HOME/.local/lib/wireshark/extcap
cp fortigate-extcap $HOME/.local/lib/wireshark/extcap/fortigate-extcap
```

## Known limitations

- Capture speed is limited by the FortiGate's text-based hexdump output over SSH. See [Help Documentation](docs/index.md#known-limitations) for details.

## Windows Defender false positive
The Windows binary may be flagged by Microsoft Defender (`Trojan:Win32/Wacatac.B!ml`). This is a known false positive affecting Go binaries that use SSH and cryptography libraries. The source code is fully open and available in this repository.

To resolve this, add an exclusion in Windows Defender for the extcap folder.

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).
