# FortiGate Extcap Plugin

This plugin lets you capture packets directly from a FortiGate firewall into Wireshark over SSH.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Starting First Capture](#starting-first-capture)
- [Configuration](#configuration)
- [Capture Filter Examples](#capture-filter-examples)
- [Security Recommendations](#security-recommendations)
- [Known Limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [How It Works](#how-it-works)
- [More Information](#more-information)

---

## Quick Start

Already have Wireshark installed? Here's the short version:

1. Download the binary for your platform from the [Releases](https://github.com/sanderzegers/fortigate-extcap/releases/) page.
2. Copy it to your Wireshark extcap folder: open Wireshark, go to **Help → About Wireshark → Folders → Personal Extcap Path**, and click the location to open it.
3. Linux/macOS only: make the binary executable: `chmod a+x fortigate-extcap`
4. Restart Wireshark. The plugin appears as **Fortigate Remote Capture** in the capture interface list.

For first-time setup or more detail, see [Installation](#installation) below.

---

## Installation

1. **Download the latest version**

   Visit the [Releases](https://github.com/sanderzegers/fortigate-extcap/releases/) page and download the version that matches your platform.

2. **Locate the personal extcap folder**

   Open Wireshark and navigate to **Help → About Wireshark → Folders → Personal Extcap Path**. Click the location to open the extcap folder.

   You can install extcap plugins in either the global or personal extcap path. The global path requires admin permissions but makes the plugin available to all users on the system.

   ![wireshark about folders](../images/about_wireshark_folders.png)

3. **Copy the binary to the extcap folder**

   Copy `fortigate-extcap.exe` (or the appropriate file for your platform) from the downloaded release into the extcap folder.

   On Linux or macOS, make the binary executable: `chmod a+x fortigate-extcap`

4. **Restart Wireshark**

   Restart Wireshark to load the custom Extcap extension.

---

## Starting First Capture

After successful installation, the extcap plugin should become visible as **Fortigate Remote Capture** in Wireshark's capture interface list.

- **First use:** click the gear icon to open the capture settings, configure the FortiGate address and credentials, then click **Start** to begin capturing without leaving the dialog.
- **Subsequent use:** double-clicking the interface skips the dialog and starts a capture immediately using the last saved settings.

![wireshark capture options](../images/wireshark_capture_options.png)

See [Configuration](#configuration) for a description of all available settings.

---

## Configuration

### Server Tab

![wireshark server tab](../images/wireshark_fortidump_server.png)

| Field | Description |
|---|---|
| **FortiGate Address** | IP address or hostname of the FortiGate. |
| **FortiGate SSH Port** | SSH port (default: 22) |
| **Interface** | FortiGate interface to capture on (e.g., `port1`, `any`). When set to `any`, each packet in Wireshark shows which interface it arrived on. Click on "Fetch from FortiGate" to retrieve interfaces from the FortiGate. If the interfaces are not updated, verify the FortiGate address, port, and credentials. For more detailed information, check the debug log. |
| **Packet count** | Maximum number of packets to capture. Set to `0` for unlimited. |
| **Capture Filter** | Capture filter in tcpdump syntax (e.g. `not port 443`). Leave empty to capture all traffic. The SSH management session is excluded automatically. |

**Capture Interface:** Wireshark displays the FortiGate interface name for each packet (shown in the frame details under *Interface name*). It also records whether the traffic is inbound or outbound relative to the FortiGate.

![wireshark capture details](../images/capture_packet_interface.png)

**Multi-VDOM:** The plugin automatically detects whether the FortiGate is running in multi-VDOM mode and enters the correct VDOM context before starting the capture. No manual configuration is needed.

### Authentication Tab

![wireshark authentication tab](../images/wireshark_fortidump_authentication.png)

| Field | Description |
|---|---|
| **Username** | SSH username (e.g. `admin`). Must have CLI access on the FortiGate. |
| **Password** | SSH password. Leave empty when using SSH agent authentication. When using password authentication, the password is visible in the process list for the entire duration of the capture. Use SSH agent authentication to avoid this. Passwords are not saved to disk and must be re-entered after Wireshark is closed; SSH agent authentication is not affected by this. |

The plugin supports two authentication methods, tried in this order:

1. **SSH agent**: if an SSH agent is running with a key loaded for the FortiGate, no password is needed. This is the recommended approach as no credentials appear on the command line.
2. **Password**: plain SSH password entered in the field above.

**Setting up SSH agent (Linux/macOS):**

```bash
# Optional: generate a new key pair if you don't have one yet
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
# Add your key to the agent — type your passphrase once
ssh-add ~/.ssh/id_ed25519
```

**Setting up SSH agent (Windows):**

```powershell
# Run once as administrator
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
# Optional: generate a new key pair if you don't have one yet
ssh-keygen -t ed25519 -f C:\Users\you\.ssh\id_ed25519
# Add your key to the agent
ssh-add C:\Users\you\.ssh\id_ed25519
```

For SSH agent to work, the FortiGate user must have the corresponding public key configured. Copy the contents of your `.pub` file (e.g. `~/.ssh/id_ed25519.pub`) into the FortiGate config:
```
config system admin
    edit admin
        set ssh-public-key1 "ssh-ed25519 AAAA..."
    next
end
```

**Note:** FortiGate requires a password to be set on every admin account, even when using SSH key authentication. Since this password will never be used for day-to-day access, set it to a long randomly generated string (32+ characters) and store it in a password manager.

### SSH Host Key Verification

The plugin verifies the FortiGate's SSH host key on every connection using the known_hosts file (default: `~/.ssh/known_hosts` on Linux/macOS, `C:\Users\<username>\.ssh\known_hosts` on Windows).

- **First connection**: the FortiGate's host key is stored automatically.
- **Subsequent connections**: the stored key is verified. If it doesn't match, the connection is refused. Common reasons: the FortiGate was replaced, re-imaged, or an HA cluster failed over to a unit with a different host key.

To remove the old entry and allow a fresh key to be stored, either:
- Run: `ssh-keygen -R <fortigate-address>`
- Or open the known_hosts file (`~/.ssh/known_hosts` on Linux/macOS, `C:\Users\<username>\.ssh\known_hosts` on Windows) in a text editor and delete the line that starts with the FortiGate's address or IP.

After removal, the new key is stored automatically on the next connection.

### Debug Tab

![wireshark debug tab](../images/wireshark_fortidump_debug.png)

| Field | Description |
|---|---|
| **Log level** | Verbosity of the log output. `Error` is the default. Set to `Debug` when troubleshooting. |
| **Log file** | Path to write log output to. No output is written unless a file is specified. |
| **Known Hostsfile** | Path to the SSH known_hosts file (default: `~/.ssh/known_hosts` on Linux/macOS, `C:\Users\<username>\.ssh\known_hosts` on Windows). The FortiGate host key is added automatically on first connection. |

---

## Capture Filter Examples

Filters use tcpdump syntax and are applied by the FortiGate itself before any data is sent over SSH — so a focused filter also reduces the load on the SSH stream.

| Goal | Filter |
|---|---|
| Traffic to/from one host | `host 192.168.1.100` |
| Traffic within a subnet | `net 10.10.0.0/24` |
| Web traffic only | `port 80 or port 443` |
| DNS traffic | `port 53` |
| ICMP / ping | `icmp` |
| Exclude a host | `not host 10.0.0.5` |
| TCP to a specific host and port | `host 10.0.0.1 and tcp port 443` |
| Filter by MAC address | `ether host 00:50:56:ab:12:34` |
| LLDP traffic | `ether proto 0x88cc` |
| Combine: web traffic, one subnet | `net 10.10.0.0/24 and (port 80 or port 443)` |

The SSH management session is always excluded automatically — no need to filter it manually.

---

## Security Recommendations

**Use SSH key authentication**

Passwords are visible in the process list for the entire duration of the capture. SSH agent authentication avoids this entirely. See the [Authentication Tab](#authentication-tab) for setup steps.

**Use a dedicated read-only admin account**

Create a separate FortiGate admin account with only the access needed for packet capture, rather than using the `admin` account. This limits exposure if credentials are ever compromised. See [How to create an admin user to do only packet capture](https://community.fortinet.com/fortigate-3/technical-tip-how-to-create-admin-user-to-do-only-packet-capture-187027) on the Fortinet community for step-by-step instructions.

Once the account is created, assign your SSH public key to it:

```
config system admin
    edit "wireshark"
        set ssh-public-key1 "ssh-ed25519 AAAA..."
    next
end
```

**Verify the host key on first use**

The plugin stores the FortiGate's SSH host key automatically on first connection. Before relying on this, verify the fingerprint manually: run `ssh <fortigate-address>` from a terminal and compare the displayed fingerprint against the value shown in the FortiGate web UI under System → Settings, or via CLI with `get system ssh status`.

---

## Known Limitations

Capture speed is limited by the FortiGate's `diagnose sniffer packet` command, which streams packets as a text hexdump over SSH rather than a binary protocol. Use a specific capture filter to focus on the traffic you need and avoid overloading the stream.

---

## Troubleshooting

### Wireshark shows no FortiGate extcap plugin after installing

- Make sure the binary is placed in the correct extcap folder: *Help → About Wireshark → Folders → Personal Extcap Path*
- On Linux/macOS, make sure the binary is executable: `chmod +x fortigate-extcap`

### Authentication failed

- Verify the username has CLI access on the FortiGate (not just web UI access).
- If using SSH agent, confirm the agent is running (`ssh-add -l`) and the FortiGate user has the public key configured.
- If using password, verify the password is correct.
- If the error mentions a host key problem, see [Host key mismatch error](#host-key-mismatch-error) below.

### Host key mismatch error

- The FortiGate's SSH host key has changed. This can happen after a replacement, re-image, or HA failover to a unit with a different host key. Remove the old entry with: `ssh-keygen -R <fortigate-address>`

### Capture starts but no packets appear

- Your capture filter may be too restrictive, or the interface name is wrong. Try `any` as the interface and leave the capture filter empty.

### Packets missing from capture

- FortiGate's NP offloading accelerates traffic through dedicated hardware processors, bypassing the software sniffer. To capture this traffic, temporarily disable NP offloading on the relevant firewall policy and re-enable it when done:

```
config firewall policy
    edit <id>
        set auto-asic-offload disable
    next
end
```

---

## How It Works

```
  ┌──────────────────────────────────────────┐
  │ FortiGate                                │
  │  diagnose sniffer packet <if> <filter> 6 │
  │  → streams packets as text hexdump       │
  └─────────────────────┬────────────────────┘
                        │ SSH tunnel
                        ▼
  ┌──────────────────────────────────────────┐
  │ fortigate-extcap plugin                  │
  │  parse hexdump                           │
  │  extract: bytes, interface, direction    │
  │  → convert to PCAPng frames              │
  └─────────────────────┬────────────────────┘
                        │ PCAPng stream
                        ▼
  ┌──────────────────────────────────────────┐
  │ Wireshark                                │
  │  live capture display                    │
  └──────────────────────────────────────────┘
```

The plugin connects to the FortiGate over SSH and runs `diagnose sniffer packet <interface> '<filter>' 6`. The `6` is a verbosity level that makes the FortiGate output each captured packet as a timestamped text hexdump.

The SSH management session is excluded automatically. The plugin determines its own local and remote IP addresses and prepends a `not (host <localip> and host <remoteip> and port <dstport>)` expression to any filter the user enters, so the capture traffic never includes the SSH connection itself.

The plugin reads the hexdump output in real time, extracts the raw packet bytes along with the interface name and traffic direction (inbound/outbound), and converts each packet into PCAPng format. Wireshark receives this as a standard live capture stream.

Because packets travel as text over SSH, throughput is lower than a native binary capture. On busy interfaces, use a capture filter to focus on the traffic you need.

---

## More Information

- [GitHub Repository](https://github.com/sanderzegers/fortigate-extcap)
- [Report an Issue](https://github.com/sanderzegers/fortigate-extcap/issues)
