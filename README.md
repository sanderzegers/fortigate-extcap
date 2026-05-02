# Wireshark Extcap extension for FortiGate

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

1. Download the binary for your platform from the [Releases](https://github.com/sanderzegers/fortigate-extcap/releases/) page.
2. Copy it to your Wireshark extcap folder: open Wireshark, go to **Help → About Wireshark → Folders → Personal Extcap Path**, and click the location to open it.
3. Linux/macOS only: make the binary executable: `chmod a+x fortigate-extcap`
4. Restart Wireshark. The plugin appears as **FortiGate Remote Capture** in the capture interface list.

For more detail, see the [Help Documentation](docs/index.md#installation).

## Usage

Once installed, the plugin appears in Wireshark's capture options as **FortiGate Remote Capture (SSH)**. The interface is listed as `fortidump` — this is the plugin's internal identifier. Click the gear icon to enter the FortiGate address, credentials, and capture settings, then double-click the interface to start capturing.

For detailed configuration, authentication setup, and troubleshooting, see the [Help Documentation](docs/index.md).

## Building from Source

To build the binary on your local machine, make sure Go and Git are installed. 
You can find the plugin folder location in the installation instructions.

Prerequisites: go and git (example for Debian-based systems):
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

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).
