package main

// Wireshark EXTCAP extension for capturing packets on a Fortigate.
// Tested with FortiOS 7.4.6, FortiOS 7.2.10
// Author: Sander Zegers
// Version: 0.0.3alpha
// License: GNU General Public License v2.0

//TODO: Optimize singlecommand
//TODO: SSH Certificate Authentication
//TODO: SSH Host Key verification
//TODO: pre-login-banner / post-login-banner support

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type networkPacket struct {
	timestampSec       uint32
	timestampMsec      uint32
	interfaceName      string
	interfaceDirection string
	datalength         uint32
	data               []byte
}

const (
	logLevelDebug = 0
	logLevelInfo  = 1
	logLevelWarn  = 2
	logLevelError = 3
)

const (
	errorUsage     = 0
	errorArg       = 1
	errorInterface = 2
	errorFifo      = 3
	errorDelay     = 4
)

type sshShell struct {
	session   *ssh.Session
	bufferIn  io.WriteCloser
	bufferOut io.Reader
}

var currentLogLevel = logLevelError
var captureStartTimestamp int64 //Timestamp when packet capture was launched
var debugLogEnabled = false
var vdomCheckEnabled = false
var sshKnownHostsfile string

// Store debug messages in log file, if debugLogEnabled is set to true
func debuglog(level int, format string, args ...interface{}) {

	if debugLogEnabled {
		formattedMsg := format

		if len(args) > 0 {
			formattedMsg = fmt.Sprintf(format, args...)
		}

		if level >= currentLogLevel {
			log.Printf("%s", formattedMsg)
		}
	}
}

// Add sinlgle packet (struct networkPacket) to existing pcap file
func addPacketToPcapFile(file *os.File, packet networkPacket) error {
	// Helper to write data with LittleEndian and check for errors
	write := func(data interface{}) error {
		return binary.Write(file, binary.LittleEndian, data)
	}

	if err := write(packet.timestampSec); err != nil {
		return err
	}

	if err := write(packet.timestampMsec); err != nil {
		return err
	}

	// Captured packet length
	if err := write(packet.datalength); err != nil {
		return err
	}

	// Original packet length
	if err := write(packet.datalength); err != nil {
		return err
	}

	if err := write(packet.data); err != nil {
		return err
	}
	return nil
}

// Create the PCAP File header
func createPcapFile(filename string) (*os.File, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	// Pcap file header
	file.Write([]byte{
		0xD4, 0xC3, 0xB2, 0xA1, //Magic number
		0x02, 0x00, //Version Major (2)
		0x04, 0x00, //Version Minor (4)
		0x00, 0x00, 0x00, 0x00, //Timezone (UTC)
		0x00, 0x00, 0x00, 0x00, //Time accuracy (0 unkown)
		0xFF, 0xFF, 0x00, 0x00, //Snapshot Length (65535 Bytes)
		0x01, 0x00, 0x00, 0x00, //Linkheader type (1 Ethernet)
	})
	return file, err
}

// Extracts a single block/packet from the diagnose sniffer output, containing time, interface and packedata
func extractSinglePacket(input_data *string) (*networkPacket, error) {
	textPacketRegex, _ := regexp.Compile(`(?ms)(\d+)\.(\d*) (.*?) (.*?) (.*?)\.*?\n(.*?)\n\n`) //Extract single packets from text output
	packetDataRegex, _ := regexp.Compile(`(?ms)0x[0-9a-f]{4}\s*(.*?[0-9a-f]{4}.*?)\s{1,}\S*$`) //Extract packet data bytes only from the single packet

	packet := networkPacket{}

	/*
	   capture group 1: packet time (secs)
	   capture group 2: packet time (msec)
	   capture group 3: interface
	   capture group 4: direction (in, out, --)
	   capture group 5: tcpdump comment
	   capture group 6: hexdump packet bytes, offset, hex, ascii
	*/

	matches := textPacketRegex.FindAllStringSubmatch(*input_data, -1)

	if matches != nil {
		for _, match := range matches { //should never return more than 1 match
			debuglog(logLevelInfo, "\n\n\nmatches found %d", len(matches))
			debuglog(logLevelDebug, "\nFull match: %s", match[0])
			for i, group := range match[1:] {

				switch {
				case i == 0:
					debuglog(logLevelInfo, "Sec: %s\n", group)
					temp, _ := strconv.ParseUint(group, 10, 32)
					packet.timestampSec = uint32(temp) + uint32(captureStartTimestamp)
				case i == 1:
					debuglog(logLevelInfo, "Msec: %s\n", group)
					temp, _ := strconv.ParseUint(group, 10, 32)
					packet.timestampMsec = uint32(temp)
				case i == 2:
					debuglog(logLevelInfo, "Interface: %s\n", group)
					packet.interfaceName = group
				case i == 3:
					debuglog(logLevelInfo, "Direction: %s\n", group)
					packet.interfaceDirection = group
				case i == 4:
					//Ignore TCPDump comment
				case i == 5:
					packetData := ""
					submatch := packetDataRegex.FindAllStringSubmatch(group, -1)
					if submatch != nil {
						for _, matchie := range submatch {
							for _, groupie := range matchie[1:] {
								packetData = packetData + groupie
							}
						}
					}
					debuglog(logLevelDebug, "packetData: %s\n", packetData)
					packetData = strings.ReplaceAll(packetData, " ", "")
					packet.data, _ = hex.DecodeString(packetData)
					packet.datalength = uint32(len(packet.data))
					debuglog(logLevelInfo, "packetLength: %d\n", packet.datalength)
				}

			}
			*input_data = strings.Replace(*input_data, match[0], "", 1) // Remove extracted packet from buffer
		}
		return &packet, nil
	}
	return nil, errors.New("no packet found")
}

func extcap_config(iface string) {

	// Server Tab
	fmt.Println("arg {number=0}{call=--host}{display=Fortigate Address}{type=string}{tooltip=The remote Fortigate. It can be both an IP address or a hostname}{required=true}{group=Server}")
	fmt.Println("arg {number=1}{call=--port}{display=Fortigate SSH Port}{type=unsigned}{tooltip=The remote SSH host port (1-65535)}{range=1,65535}{default=22}{required=true}{group=Server}")
	fmt.Println("arg {number=2}{call=--capture-filter}{display=Capture filter}{type=string}{tooltip=tcpdump filter}{default=not port 22}{required=true}{group=Server}")
	fmt.Println("arg {number=3}{call=--capture-interface}{display=Interface}{type=string}{tooltip=filter by interface}{default=any}{required=true}{group=Server}")

	// Authentication Tab
	fmt.Println("arg {number=4}{call=--username}{display=Username}{type=string}{tooltip=The remote SSH username. If not provided, the current user will be used}{required=true}{group=Authentication}")
	fmt.Println("arg {number=5}{call=--password}{display=Password}{type=password}{tooltip=The SSH password, used when other methods (SSH agent or key files) are unavailable.}{group=Authentication}")
	fmt.Println("arg {number=6}{call=--sshkey}{display=Path to SSH Private Key}{type=fileselect}{tooltip=The path on the local filesystem of the private ssh key}{group=Authentication}")

	// Debug Tab
	fmt.Println("arg {number=7}{call=--log-level}{display=Set the log level}{type=selector}{tooltip=The remote SSH username. If not provided, the current user will be used}{required=false}{group=Debug}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelError) + "}{display=Error}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelWarn) + "}{display=Warning}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelInfo) + "}{display=Info}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelDebug) + "}{display=Debug}")
	fmt.Println("arg {number=8}{call=--log-file}{display=Use a file for logging}{type=fileselect}{tooltip=Set a file where log messages are written}{required=false}{group=Debug}")
	fmt.Println("arg {number=9}{call=--vdom}{display=Multi-VDOM check}{type=boolean}{tooltip=Fortigate VDOM Support}{default=false}{required=false}{group=Debug}")
	fmt.Println("arg {number=10}{call=--packetlimit}{display=Packet count}{type=unsigned}{tooltip=Limit the maximum packet count. 0=unlimited}{default=1000}{required=true}{group=Debug}")
	fmt.Println("arg {number=11}{call=--knownhosts}{display=Known Hostsfile}{type=fileselect}{tooltip=Path to knownhosts file}{required=true}{default=" + sshKnownHostsfile + "}{group=Debug}")

}

func extcap_version() {
	fmt.Println("extcap {version=0.0.3-alpha}{help=https://sanderzegers.github.io/fortigate-extcap/}")
}

func extcap_interfaces() {
	fmt.Println("interface {value=fortidump}{display=Fortigate Remote Capture (SSH)}")
}

func main() {

	homeDir, err := os.UserHomeDir()

	if err != nil {
		debuglog(logLevelError, "WARNING: Unable to determine user home directory: %v. Falling back to temp directory.", err)
		homeDir = os.TempDir()
	}

	sshKnownHostsfile = filepath.Join(homeDir, ".ssh", "known_hosts")

	// Default extcap parameters
	extcapCapture := flag.Bool("capture", false, "Start the capture")
	extcapInterfaces := flag.Bool("extcap-interfaces", false, "Provide a list of interfaces to capture from")
	extcapInterface := flag.String("extcap-interface", "", "Provide the interface to capture from")
	extcapVersion := flag.String("extcap-version", "", "Shows the version of this utility")
	extcapDtls := flag.Bool("extcap-dlts", false, "Provide a list of dlts for the given interface")
	extcapConfig := flag.Bool("extcap-config", false, "Provide a list of configurations for the given interface")
	_ = flag.String("extcap-capture-filter", "", "Used together with capture to provide a capture filter") // TODO: Find better way to integrate the wireshark filter
	extcapFifo := flag.String("fifo", "", "Use together with capture to provide the fifo to dump data to")

	// Custom extcap parameters
	extcapHost := flag.String("host", "", "The remote SSH hots (ip or domain name)")
	extcapPort := flag.Int("port", 22, "The remote SSH port")
	extcapUsername := flag.String("username", "", "The remote SSH Username")
	extcapPassword := flag.String("password", "", "The remote SSH Password")
	extcapSshKey := flag.String("sshkey", "", "Path of ssh key used for passwordless authentication")
	extcapCaptureFilter := flag.String("capture-filter", "none", "Diagnose sniffer packet capture filter")
	extcapCaptureInterface := flag.String("capture-interface", "any", "Capture interface on Fortigate")
	extcapLogLevel := flag.Int("log-level", logLevelError, "Loglevel Debug(0) - Error(3) / Default 3")
	extcapLogFile := flag.String("log-file", "", "Log filename")
	extcapVdomCheck := flag.String("vdom", "false", "Enable VDOM check, and enter management VDOM")
	extcapPacketLimit := flag.Int("packetlimit", 1000, "Limit packet capture count")
	extcapKnownHostsFile := flag.String("knownhosts", sshKnownHostsfile, "Path of ssh known_hosts file")

	flag.Parse()

	sshKnownHostsfile = *extcapKnownHostsFile

	currentLogLevel = *extcapLogLevel

	if *extcapVdomCheck == "true" {
		vdomCheckEnabled = true
	}

	if *extcapLogFile != "" {

		logfile, err := os.OpenFile(*extcapLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to open log file")
			debuglog(logLevelError, "Fatal: Failed to open log file:  %s", err)
		}
		defer logfile.Close()

		log.SetOutput(logfile)

		debugLogEnabled = true

		debuglog(logLevelInfo, "created log file %s", *extcapLogFile)

	}

	debuglog(logLevelDebug, "logLevelDebug")
	debuglog(logLevelInfo, "logLevelInfo")
	debuglog(logLevelWarn, "logLevelWarn")
	debuglog(logLevelError, "logLevelError")

	allArgs := strings.Join(os.Args[1:], " ")

	debuglog(logLevelDebug, allArgs)

	if !*extcapInterfaces && *extcapInterface == "" {
		fmt.Println("An interface must be provided or the selection must be displayed")
		return
	}

	if *extcapInterfaces {
		extcap_version()
		extcap_interfaces()
		return
	}

	if *extcapConfig {
		extcap_config("")
		return
	}

	if *extcapDtls {
		fmt.Println("dlt {number=1}{name=EN10MB}{display=Ethernet}")
		return
	}

	if *extcapVersion != "" {
		extcap_version()
	}

	if *extcapCapture {
		if *extcapHost == "" {
			fmt.Fprintln(os.Stderr, "No SSH hostname defined")
			debuglog(logLevelError, "Fatal: No SSH hostname defined")
			os.Exit(errorArg)
		}
		if *extcapUsername == "" {
			fmt.Fprintln(os.Stderr, "No SSH username defined")
			debuglog(logLevelError, "Fatal: No SSH username defined")
			os.Exit(errorArg)
		}
		if *extcapPassword == "" && *extcapSshKey == "" {
			fmt.Fprintln(os.Stderr, "No SSH password or SSH Key defined")
			debuglog(logLevelError, "Fatal: No SSH password or SSH Key defined")
			os.Exit(errorArg)
		}
		if *extcapFifo == "" {
			fmt.Fprintln(os.Stderr, "No fifo file defined")
			debuglog(logLevelError, "Fatal: No fifo file defined")
			os.Exit(errorFifo)
		}

		err := startCaptureSession(extcapFifo, extcapUsername, extcapPassword, extcapHost, extcapPort, extcapCaptureInterface, extcapCaptureFilter, extcapPacketLimit)
		if err != nil {
			//fmt.Fprintln(os.Stderr, err)
			debuglog(logLevelError, "Fatal: %s", err)
			os.Exit(errorDelay)
		}

	}

}

func checkKnownHosts() (ssh.HostKeyCallback, error) {
	f, err := os.OpenFile((sshKnownHostsfile), os.O_CREATE, 0600)
	if err != nil {
		debuglog(logLevelError, "sshKnownHostsfile failed: %s", err)
		return nil, err
	}
	f.Close()

	kh, err := knownhosts.New(sshKnownHostsfile)
	if err != nil {
		debuglog(logLevelError, "knownhosts failed: %s", err)
		return nil, err
	}
	return kh, nil
}

func addHostKey(host string, remote net.Addr, pubKey ssh.PublicKey) error {
	// add host key if host is not found in known_hosts, error object is return, if nil then connection proceeds,
	// if not nil then connection stops.

	khFilePath := filepath.Join(sshKnownHostsfile)

	f, fErr := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if fErr != nil {
		return fErr
	}
	defer f.Close()

	knownHosts := knownhosts.Normalize(remote.String())
	_, fileErr := f.WriteString(knownhosts.Line([]string{knownHosts}, pubKey))
	return fileErr
}

func newSSHSession(username *string, password *string, hostname *string, port *int) (*sshShell, error) {
	var (
		keyErr *knownhosts.KeyError
	)

	debuglog(logLevelDebug, "newSSHSession()")

	sshShellSession := sshShell{}

	config := &ssh.ClientConfig{
		User: *username,
		Auth: []ssh.AuthMethod{
			ssh.Password(*password),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			kh, kHErr := checkKnownHosts()
			hErr := kh(host, remote, pubKey)
			if kHErr != nil {
				return kHErr
			} else if errors.As(hErr, &keyErr) && len(keyErr.Want) > 0 {
				fmt.Fprintln(os.Stderr, "SSH Public key authentication failed, check known_hosts file")
				debuglog(logLevelError, "Public key does not match known_hosts file: %s", host)
				return keyErr
			} else if errors.As(hErr, &keyErr) && len(keyErr.Want) == 0 {
				debuglog(logLevelInfo, "%s is not trusted, adding key to known_hosts file.", host)
				return addHostKey(host, remote, pubKey)
			}
			debuglog(logLevelInfo, "Public key found for %s in trusted hosts", host)
			return nil
		}),
		HostKeyAlgorithms: []string{"ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384"},
	}

	client, err := ssh.Dial("tcp", *hostname+":"+strconv.Itoa(*port), config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %s", err)
	}

	sshShellSession.session, err = client.NewSession()
	if err != nil {
		debuglog(logLevelError, "Session Error: %s", err)
		return nil, err
	}

	sshShellSession.bufferIn, err = sshShellSession.session.StdinPipe()
	if err != nil {
		debuglog(logLevelError, "StdinPipe Error: %s", err)
		return &sshShellSession, err
	}
	sshShellSession.bufferOut, err = sshShellSession.session.StdoutPipe()
	if err != nil {
		debuglog(logLevelError, "StdoutPipe Error: %s", err)
		return &sshShellSession, err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}

	err = sshShellSession.session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		debuglog(logLevelError, "request for pseudo terminal failed: %s", err)
		return nil, err
	}

	err = sshShellSession.session.Shell()
	if err != nil {
		debuglog(logLevelError, "failed to start shell: %s", err)
		return nil, err
	}

	// Retrieve Shell prompt

	sshShellSession.bufferIn.Write([]byte("\n"))

	lineBuffer := new(string)
	scanner := bufio.NewScanner(sshShellSession.bufferOut)

	for scanner.Scan() {
		*lineBuffer += scanner.Text() + ""
		break
	}

	return &sshShellSession, err

}

func endSSHSession(sshShellSession *sshShell) error {
	debuglog(logLevelDebug, "endSSHSession()")
	sshShellSession.session.Close()
	return nil
}

func runSingleCommand(sshShellSession *sshShell, cmd string) (string, error) {
	debuglog(logLevelDebug, "runSingleCommand()")

	commandPromptRegexString := `(?ms)^\r\n$`

	commandpromptRegex, _ := regexp.Compile(commandPromptRegexString) //Extract single packets from text output

	lineBuffer := new(string)

	sshShellSession.bufferIn.Write([]byte(cmd + "\n"))

	reader := bufio.NewReader(sshShellSession.bufferOut)

	for {
		line, err := reader.ReadString('\n')
		*lineBuffer += line
		debuglog(logLevelDebug, "%s", line)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		matches := commandpromptRegex.FindAllStringSubmatch(line, -1)
		if matches != nil {
			break
		}
	}

	debuglog(logLevelError, "singleCommand() ended")

	return *lineBuffer, nil
}

// Run sniffer command, wo don't expect to return from here unless packet count reached
func runSnifferCommand(sshShellSession *sshShell, cmd string, pcapfile *os.File) error {

	debuglog(logLevelDebug, "runSnifferCommand()")

	lineBuffer := new(string)

	//io.ReadAll(sshShellSession.bufferOut)
	scanner := bufio.NewScanner(sshShellSession.bufferOut)

	sshShellSession.bufferIn.Write([]byte(cmd + "\n"))
	sshShellSession.bufferIn.Write([]byte("###EndOfCaptureReached###\n"))

	pcapCompileError, _ := regexp.Compile("(?ms)^pcap_compile:(.*)|^pcap_activate:(.*)|^Command fail(.*)")
	pcapCompileEndOfCapture, _ := regexp.Compile("###EndOfCaptureReached###")

	for scanner.Scan() {
		*lineBuffer += scanner.Text() + "\n"
		matches := pcapCompileError.FindAllStringSubmatch(*lineBuffer, -1)
		if matches != nil {
			for _, match := range matches {
				return (fmt.Errorf("command line error: %s", match[0][1:]))
			}
		}
		matches = pcapCompileEndOfCapture.FindAllStringSubmatch(*lineBuffer, -1)
		if matches != nil {
			break
		}

		debuglog(logLevelDebug, "Reading command: %s", *lineBuffer)
		if packet, err := extractSinglePacket(lineBuffer); err == nil {
			if err := addPacketToPcapFile(pcapfile, *packet); err != nil {
				debuglog(logLevelError, "Packet write error: %s", err)
				return err
			}
		}
	}

	debuglog(logLevelError, "Capture ended")

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func startCaptureSession(filename *string, username *string, password *string, hostname *string, port *int, captureInterface *string, captureFilter *string, packetlimit *int) error {

	pcap_file, _ := createPcapFile(*filename)

	defer pcap_file.Close()

	sshSession, err := newSSHSession(username, password, hostname, port)
	if err != nil {
		return err
	}

	defer endSSHSession(sshSession)

	result := ""

	sniffCommand := fmt.Sprintf(`diagnose sniffer packet %s "%s" 6 %d`, *captureInterface, *captureFilter, *packetlimit)

	if vdomCheckEnabled {

		vdomtext, err := runSingleCommand(sshSession, "get system status | grep \"Current virtual\"")
		if err != nil {
			return err
		}

		vdomtext = strings.TrimSpace(strings.Split(vdomtext, ":")[1])
		debuglog(logLevelInfo, vdomtext)

		result, err = runSingleCommand(sshSession, "config vdom")
		if err != nil {
			return err
		}

		debuglog(logLevelInfo, result)

		result, err = runSingleCommand(sshSession, fmt.Sprintf("edit %s", vdomtext))
		if err != nil {
			return err
		}

		debuglog(logLevelInfo, result)

	}

	err = runSnifferCommand(sshSession, sniffCommand, pcap_file)
	if err != nil {
		return err
	}

	debuglog(logLevelError, "here")

	return nil
}
