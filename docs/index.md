# FortiGate Extcap Plugin — Help

This plugin lets you capture packets directly from a FortiGate firewall into Wireshark over SSH.

---

## Configuration

### Server Tab

| Field | Description |
|---|---|
| **FortiGate Address** | IP address or hostname of the FortiGate |
| **FortiGate SSH Port** | SSH port (default: 22) |
| **Capture Filter** | Traffic filter in tcpdump syntax (e.g. `not port 22`). Use a specific filter to focus on the traffic you need. |
| **Interface** | FortiGate interface to capture on (e.g. `port1`, `any`) |
| **Packet count** | Maximum number of packets to capture. Set to `0` for unlimited. |

### Authentication Tab

| Field | Description |
|---|---|
| **Username** | SSH username (e.g. `admin`). Must have CLI access on the FortiGate. |
| **Password** | SSH password. Leave empty when using SSH agent authentication. |

The plugin supports two authentication methods, tried in this order:

1. **SSH agent** — if an SSH agent is running with a key loaded for the FortiGate, no password is needed. This is the recommended approach as no credentials appear on the command line.
2. **Password** — plain SSH password entered in the field above.

**Setting up SSH agent (Linux/macOS):**
```bash
# Optional: generate a new key pair if you don't have one yet
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
# Add your key to the agent — type your passphrase once
ssh-add ~/.ssh/id_ed25519
```
Then leave the Password field empty in Wireshark.

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

For SSH agent to work, the FortiGate user must have the corresponding public key configured. The public key is the `.pub` file generated alongside your private key (e.g. `~/.ssh/id_ed25519.pub` on Linux/macOS or `C:\Users\you\.ssh\id_ed25519.pub` on Windows). Copy its contents into the FortiGate config:
```
config system admin
    edit admin
        set ssh-public-key1 "ssh-rsa AAAA..."
    next
end
```

> **Note:** FortiGate requires a password to be set on every admin account, even when using SSH key authentication. Since this password will never be used for day-to-day access, set it to a long randomly generated string (32+ characters). Store it in a password manager.

### Debug Tab

| Field | Description |
|---|---|
| **Multi-VDOM check** | Enable when the FortiGate runs in multi-VDOM mode. The plugin will automatically enter the management VDOM before capturing. |
| **Log level** | Verbosity of the log output. `Error` is the default. Set to `Debug` when troubleshooting. |
| **Log file** | Path to write log output to. No output is written unless a file is specified. |
| **Known Hostsfile** | Path to the SSH known_hosts file (default: `~/.ssh/known_hosts`). The FortiGate's host key is added automatically on first connection. |

---

## Known Limitations

- Capture speed is limited by the FortiGate's `diagnose sniffer packet` command, which streams packets as a text hexdump over SSH rather than a binary protocol. Use a specific capture filter to focus on the traffic you need and avoid overloading the stream.
- Wireshark may show a warning on first connection while the host key is being added to known_hosts — this is expected.

---

## Troubleshooting

**Wireshark shows no Fortigate extcap Plugin after installing**
- Make sure the binary is placed in the correct extcap folder: *Help → About Wireshark → Folders → Personal Extcap Path*
- On Linux/macOS, make sure the binary is executable: `chmod +x fortigate-extcap`

**Authentication failed**
- Verify the username has CLI access on the FortiGate (not just web UI access).
- If using SSH agent, confirm the agent is running (`ssh-add -l`) and the FortiGate user has the public key configured.
- If using password, verify the password is correct.

**Host key mismatch error**
- The FortiGate's SSH host key has changed. Remove the old entry with: `ssh-keygen -R <fortigate-address>`

**Capture starts but no packets appear**
- Your capture filter may be too restrictive, or the interface name is wrong. Try `any` as the interface and `not port 22` as the filter.

---

## More Information

- [GitHub Repository](https://github.com/sanderzegers/fortigate-extcap)
- [Report an Issue](https://github.com/sanderzegers/fortigate-extcap/issues)
