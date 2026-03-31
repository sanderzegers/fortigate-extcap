package main

// Wireshark EXTCAP extension for capturing packets on a Fortigate.
// Tested with FortiOS 7.4.6, FortiOS 7.2.10, FortiOS 7.6.5
// Author: Sander Zegers
// Version: 0.5.1
// License: GNU General Public License v2.0

// TODO: Fortigate pre-login-banner / post-login-banner support

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
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	client    *ssh.Client
	session   *ssh.Session
	bufferIn  io.WriteCloser
	bufferOut io.Reader
	scanner   *bufio.Scanner // shared scanner — created once to avoid double-buffering
}

var currentLogLevel = logLevelError
var captureStartTimestamp int64 // Timestamp when packet capture was launched
var debugLogEnabled = false
var sshKnownHostsfile string

// activeSession is set while a capture is running so the signal handler can
// close the SSH connection and let runSnifferCommand exit cleanly.
var activeSession *sshShell

// buildDate is injected at compile time via -ldflags "-X main.buildDate=..."
var buildDate = "unknown"

// Store debug messages in log file, if debugLogEnabled is set to true
func debuglog(level int, format string, args ...interface{}) {
	if !debugLogEnabled || level < currentLogLevel {
		return
	}
	log.Print(fmt.Sprintf(format, args...))
}

// writeSectionHeaderBlock writes a PCAPng Section Header Block.
func writeSectionHeaderBlock(file *os.File) error {
	const blockLen uint32 = 28
	write := func(v interface{}) error { return binary.Write(file, binary.LittleEndian, v) }
	for _, v := range []interface{}{
		uint32(0x0A0D0D0A), // Block Type
		blockLen,            // Block Total Length
		uint32(0x1A2B3C4D), // Byte-Order Magic
		uint16(1),           // Major Version
		uint16(0),           // Minor Version
		int64(-1),           // Section Length (unknown)
		blockLen,            // Block Total Length (repeated)
	} {
		if err := write(v); err != nil {
			return err
		}
	}
	return nil
}

// writeInterfaceDescriptionBlock writes a PCAPng Interface Description Block.
// It must be written before any Enhanced Packet Blocks that reference this interface.
func writeInterfaceDescriptionBlock(file *os.File, ifName string) error {
	write := func(v interface{}) error { return binary.Write(file, binary.LittleEndian, v) }
	nameBytes := []byte(ifName)
	namePad := (4 - (len(nameBytes) % 4)) % 4
	// Options: if_name code(2)+length(2)+value+padding + opt_endofopt(4)
	optLen := 0
	if len(nameBytes) > 0 {
		optLen = 4 + len(nameBytes) + namePad + 4
	}
	// Block = Type(4)+TotalLen(4)+LinkType(2)+Reserved(2)+SnapLen(4)+Options+TotalLen(4)
	blockLen := uint32(4 + 4 + 8 + optLen + 4)
	if err := write(uint32(0x00000001)); err != nil { return err } // Block Type: IDB
	if err := write(blockLen); err != nil { return err }
	if err := write(uint16(1)); err != nil { return err }    // Link Type: Ethernet
	if err := write(uint16(0)); err != nil { return err }    // Reserved
	if err := write(uint32(65535)); err != nil { return err } // Snap Length
	if len(nameBytes) > 0 {
		if err := write(uint16(2)); err != nil { return err }                 // Option: if_name
		if err := write(uint16(len(nameBytes))); err != nil { return err }    // Option Length
		if _, err := file.Write(nameBytes); err != nil { return err }
		if namePad > 0 {
			if _, err := file.Write(make([]byte, namePad)); err != nil { return err }
		}
		if err := write(uint32(0)); err != nil { return err } // opt_endofopt
	}
	return write(blockLen)
}

// writeEnhancedPacketBlock writes a PCAPng Enhanced Packet Block.
// ifID must match the index of a previously written Interface Description Block.
func writeEnhancedPacketBlock(file *os.File, packet networkPacket, ifID int) error {
	write := func(v interface{}) error { return binary.Write(file, binary.LittleEndian, v) }
	// Timestamp in microseconds since epoch (PCAPng default resolution)
	tsUs := uint64(packet.timestampSec)*1_000_000 + uint64(packet.timestampMsec)
	dataLen := len(packet.data)
	dataPad := (4 - (dataLen % 4)) % 4
	// EPB Flags option bits 0-1: 00=unknown, 01=inbound, 10=outbound
	var dirFlags uint32
	switch strings.ToLower(packet.interfaceDirection) {
	case "in":
		dirFlags = 1
	case "out":
		dirFlags = 2
	}
	// Options: epb_flags code(2)+length(2)+value(4) + opt_endofopt(4) = 12 bytes
	const optLen = 12
	// Block = Type(4)+TotalLen(4)+IfID(4)+TsHigh(4)+TsLow(4)+CapLen(4)+OrigLen(4)+Data+Pad+Opts+TotalLen(4)
	blockLen := uint32(4 + 4 + 4 + 4 + 4 + 4 + 4 + dataLen + dataPad + optLen + 4)
	if err := write(uint32(0x00000006)); err != nil { return err } // Block Type: EPB
	if err := write(blockLen); err != nil { return err }
	if err := write(uint32(ifID)); err != nil { return err }
	if err := write(uint32(tsUs >> 32)); err != nil { return err }         // Timestamp High
	if err := write(uint32(tsUs & 0xFFFFFFFF)); err != nil { return err }  // Timestamp Low
	if err := write(uint32(dataLen)); err != nil { return err }             // Captured Length
	if err := write(uint32(dataLen)); err != nil { return err }             // Original Length
	if _, err := file.Write(packet.data); err != nil { return err }
	if dataPad > 0 {
		if _, err := file.Write(make([]byte, dataPad)); err != nil { return err }
	}
	if err := write(uint16(2)); err != nil { return err }  // Option Code: epb_flags
	if err := write(uint16(4)); err != nil { return err }  // Option Length
	if err := write(dirFlags); err != nil { return err }   // Option Value
	if err := write(uint32(0)); err != nil { return err }  // opt_endofopt
	return write(blockLen)
}

// openFile opens a file or Windows named pipe for writing.
// Named pipes (\\.\pipe\...) must be opened write-only without create/truncate
// flags — those flags are invalid for pipes and corrupt the pipe state.
// Regular files are created/truncated as normal.
func openFile(filename string) (*os.File, error) {
	if strings.HasPrefix(filename, `\\.\pipe\`) {
		return os.OpenFile(filename, os.O_WRONLY, 0)
	}
	return os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
}

// createPcapngFile opens the output file and writes a PCAPng Section Header Block.
// Retry logic handles Windows named pipes that may not be ready immediately.
func createPcapngFile(filename string) (*os.File, error) {
	var file *os.File
	var err error
	for i := 0; i < 10; i++ {
		debuglog(logLevelDebug, "createPcapngFile: attempt %d", i+1)
		file, err = openFile(filename)
		if err == nil {
			break
		}
		debuglog(logLevelDebug, "createPcapngFile: attempt %d failed: %s", i+1, err)
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	if err := writeSectionHeaderBlock(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write pcapng header: %w", err)
	}
	return file, nil
}

// headerLineRe matches the timestamp/interface/direction header of a sniffer packet.
// Groups: 1=secs, 2=usecs, 3=interface, 4=direction
var headerLineRe = regexp.MustCompile(`^(\d+)\.(\d+)\s+(\S+)\s+(\S+)`)

// commandPromptRe matches the blank line that FortiGate sends after command output.
// bufio.Scanner with default ScanLines strips \r from \r\n, so a bare \r\n line → "".
var commandPromptRe = regexp.MustCompile(`^\r?$`)

// pcapErrorRe matches sniffer startup error messages returned by FortiGate.
var pcapErrorRe = regexp.MustCompile(`^pcap_compile:|^pcap_activate:|^Command fail`)

// maxLineBufferSize is the maximum size of the line buffer in runSnifferCommand.
// If exceeded, leading content is trimmed to prevent unbounded memory growth.
const maxLineBufferSize = 1 * 1024 * 1024 // 1 MB

// isHexdumpLine returns true if line starts with a 0xNNNN offset (hexdump line).
func isHexdumpLine(line string) bool {
	if len(line) < 7 {
		return false
	}
	if line[0] != '0' || line[1] != 'x' {
		return false
	}
	for _, c := range line[2:6] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return line[6] == ' ' || line[6] == '\t'
}

// isHexGroup returns true if s is a 2- or 4-character lowercase hex string.
// This matches exactly the byte groups in FortiGate hexdump output and stops
// before the trailing ASCII rendering, which is never 2 or 4 all-lowercase-hex chars.
func isHexGroup(s string) bool {
	if len(s) != 2 && len(s) != 4 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// extractSinglePacket parses one complete packet block from the input buffer.
// A block is: one header line (timestamp/interface/direction), zero or more
// comment/description lines, one or more 0xNNNN hexdump lines, terminated by
// a blank line. Lines that do not start with 0xNNNN are skipped — this safely
// ignores CAPWAP headers, "linux cooked capture", icmp6 sum-ok, etc.
func extractSinglePacket(inputData *string) (*networkPacket, error) {
	lines := strings.Split(*inputData, "\n")

	// Find the first header line.
	headerIdx := -1
	for i, line := range lines {
		if headerLineRe.MatchString(line) {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil, errors.New("no packet found")
	}

	// Find the blank line that terminates this packet block.
	// FortiGate sometimes inserts a blank line between the timestamp header
	// and the hexdump section (e.g. before a "linux cooked capture" description
	// line). Only treat a blank line as the packet terminator once at least one
	// hexdump line has been seen — earlier blank lines are part of the format.
	//
	// Important: the buffer always ends with "\n" (each line is appended as
	// line+"\n"), so strings.Split always produces a trailing "" as its last
	// element. Exclude that artifact by searching only up to len(lines)-1.
	endIdx := -1
	foundHexLine := false
	for i := headerIdx + 1; i < len(lines)-1; i++ {
		if isHexdumpLine(lines[i]) {
			foundHexLine = true
		}
		if strings.TrimSpace(lines[i]) == "" && foundHexLine {
			endIdx = i
			break
		}
	}
	if endIdx < 0 {
		// Block not yet complete — wait for more data.
		return nil, errors.New("no packet found")
	}

	// Parse the header fields.
	m := headerLineRe.FindStringSubmatch(lines[headerIdx])
	packet := networkPacket{}
	sec, _ := strconv.ParseUint(m[1], 10, 32)
	usec, _ := strconv.ParseUint(m[2], 10, 32)
	packet.timestampSec = uint32(sec) + uint32(captureStartTimestamp)
	packet.timestampMsec = uint32(usec)
	packet.interfaceName = m[3]
	packet.interfaceDirection = m[4]

	debuglog(logLevelDebug, "Parsing packet header: sec=%d usec=%d if=%s dir=%s",
		sec, usec, packet.interfaceName, packet.interfaceDirection)

	// Collect hex bytes from hexdump lines only.
	// Each hexdump line: "0xNNNN   HHHH HHHH ... HHHH   ASCII"
	// Split on whitespace: fields[0]="0xNNNN", fields[1..N]=hex groups, rest=ASCII.
	// Stop at the first field that is not a 2- or 4-char lowercase hex group.
	var hexData strings.Builder
	for i := headerIdx + 1; i < endIdx; i++ {
		line := lines[i]
		if !isHexdumpLine(line) {
			debuglog(logLevelDebug, "Skipping non-hexdump line: %s", line)
			continue
		}
		fields := strings.Fields(line)
		// fields[0] is the "0xNNNN" offset; hex groups start at index 1.
		for _, field := range fields[1:] {
			if !isHexGroup(field) {
				break // reached the ASCII rendering section
			}
			hexData.WriteString(field)
		}
	}

	// Remove the consumed block from the buffer (preserve any lines before it).
	remaining := make([]string, 0, len(lines)-(endIdx-headerIdx+1))
	remaining = append(remaining, lines[:headerIdx]...)
	remaining = append(remaining, lines[endIdx+1:]...)
	*inputData = strings.Join(remaining, "\n")

	hexStr := hexData.String()
	if hexStr == "" {
		debuglog(logLevelInfo, "Packet block contained no hexdump lines — skipping")
		return nil, errors.New("no hex data in packet block")
	}

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		debuglog(logLevelInfo, "Hex decode error: %s (raw hex: %.60s)", err, hexStr)
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("packet decoded to zero bytes")
	}

	packet.data = data
	packet.datalength = uint32(len(data))
	debuglog(logLevelDebug, "Extracted packet: %d bytes", packet.datalength)
	return &packet, nil
}

func extcapConfig() {

	// Server Tab
	fmt.Println("arg {number=0}{call=--host}{display=Fortigate Address}{type=string}{tooltip=IP address or hostname of the FortiGate firewall}{required=true}{group=Server}")
	fmt.Println("arg {number=1}{call=--port}{display=Fortigate SSH Port}{type=unsigned}{tooltip=SSH port used to connect to the FortiGate (default: 22)}{range=1,65535}{default=22}{required=true}{group=Server}")
	fmt.Println("arg {number=2}{call=--capture-filter}{display=Capture Filter}{type=string}{tooltip=Capture filter in tcpdump syntax. Leave empty to capture all traffic. The SSH management session is excluded automatically. Example: not port 443}{required=false}{group=Server}")
	fmt.Println("arg {number=3}{call=--capture-interface}{display=Interface}{type=string}{tooltip=FortiGate interface to capture on (e.g. port1, any). Use any to capture on all interfaces.}{default=any}{required=true}{group=Server}")
	fmt.Println("arg {number=10}{call=--packetlimit}{display=Packet count}{type=unsigned}{tooltip=Maximum number of packets to capture. Set to 0 for unlimited.}{default=1000}{required=true}{group=Server}")

	// Authentication Tab
	fmt.Println("arg {number=4}{call=--username}{display=Username}{type=string}{tooltip=The remote SSH username. If not provided, the current user will be used}{required=true}{group=Authentication}")
	fmt.Println("arg {number=5}{call=--password}{display=Password}{type=password}{tooltip=The SSH password. Leave empty when using SSH agent authentication. Note: the password is visible in the process list for the entire duration of the capture. Use SSH agent authentication to avoid this.}{group=Authentication}")

	// Debug Tab
	fmt.Println("arg {number=7}{call=--log-level}{display=Log level}{type=selector}{tooltip=Verbosity of log output. Use Debug when troubleshooting.}{required=false}{group=Debug}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelError) + "}{display=Error}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelWarn) + "}{display=Warning}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelInfo) + "}{display=Info}")
	fmt.Println("value {arg=7}{value=" + strconv.Itoa(logLevelDebug) + "}{display=Debug}")
	fmt.Println("arg {number=8}{call=--log-file}{display=Log file}{type=fileselect}{tooltip=Path to write log output to. No output is written unless a file is specified.}{required=false}{group=Debug}")
	fmt.Println("arg {number=11}{call=--knownhosts}{display=Known Hostsfile}{type=fileselect}{tooltip=Path to the SSH known_hosts file. The FortiGate host key is added automatically on first connection.}{required=false}{default=" + sshKnownHostsfile + "}{group=Debug}")

}

func extcapVersion() {
	fmt.Println("extcap {version=0.5.1}{help=https://sanderzegers.github.io/fortigate-extcap/}")
}

func extcapInterfaces() {
	fmt.Println("interface {value=fortidump}{display=Fortigate Remote Capture (SSH)}")
}

// captureFilterFlag is the flag name that Wireshark may pass as multiple
// separate words. Referenced by both joinCaptureFilter and the debug-log
// quoting loop so adding a new multi-word flag only needs one edit.
const captureFilterFlag = "--capture-filter"

// joinCaptureFilter preprocesses os.Args before flag.Parse() to handle the
// case where Wireshark passes --capture-filter as multiple separate arguments
// (e.g. ["--capture-filter", "not", "port", "22"]) instead of a single quoted
// string. It joins all words after --capture-filter until the next flag into
// one argument so Go's flag parser sees them as a single value.
func joinCaptureFilter(args []string) []string {
	result := []string{args[0]}
	for i := 1; i < len(args); i++ {
		if args[i] == captureFilterFlag && i+1 < len(args) {
			result = append(result, args[i])
			i++
			filterParts := []string{}
			for i < len(args) && !strings.HasPrefix(args[i], "-") {
				filterParts = append(filterParts, args[i])
				i++
			}
			result = append(result, strings.Join(filterParts, " "))
			i-- // back up so the outer loop increment lands on the next flag
		} else {
			result = append(result, args[i])
		}
	}
	return result
}

func main() {

	os.Args = joinCaptureFilter(os.Args)

	homeDir, err := os.UserHomeDir()

	if err != nil {
		debuglog(logLevelError, "WARNING: Unable to determine user home directory: %v. Falling back to temp directory.", err)
		homeDir = os.TempDir()
	}

	sshKnownHostsfile = filepath.Join(homeDir, ".ssh", "known_hosts")

	// Default extcap parameters
	extcapCapture := flag.Bool("capture", false, "Start the capture")
	extcapInterfacesArg := flag.Bool("extcap-interfaces", false, "Provide a list of interfaces to capture from")
	extcapInterface := flag.String("extcap-interface", "", "Provide the interface to capture from")
	extcapVersionArg := flag.String("extcap-version", "", "Shows the version of this utility")
	extcapDtls := flag.Bool("extcap-dlts", false, "Provide a list of dlts for the given interface")
	extcapConfigArg := flag.Bool("extcap-config", false, "Provide a list of configurations for the given interface")
	_ = flag.String("extcap-capture-filter", "", "Used together with capture to provide a capture filter") // TODO: Find better way to integrate the wireshark filter
	extcapFifo := flag.String("fifo", "", "Use together with capture to provide the fifo to dump data to")

	// Custom extcap parameters
	extcapHost := flag.String("host", "", "The remote SSH host (ip or domain name)")
	extcapPort := flag.Int("port", 22, "The remote SSH port")
	extcapUsername := flag.String("username", "", "The remote SSH Username")
	extcapPassword := flag.String("password", "", "The remote SSH Password")
	extcapCaptureFilter := flag.String("capture-filter", "", "Diagnose sniffer packet capture filter")
	extcapCaptureInterface := flag.String("capture-interface", "any", "Capture interface on Fortigate")
	extcapLogLevel := flag.Int("log-level", logLevelError, "Loglevel Debug(0) - Error(3) / Default 3")
	extcapLogFile := flag.String("log-file", "", "Log filename")
	extcapPacketLimit := flag.Int("packetlimit", 1000, "Limit packet capture count")
	extcapKnownHostsFile := flag.String("knownhosts", sshKnownHostsfile, "Path of ssh known_hosts file")

	flag.Parse()

	sshKnownHostsfile = *extcapKnownHostsFile

	_, err = os.Stat(filepath.Dir(sshKnownHostsfile))

	if err != nil {
		if os.IsNotExist(err) {
			errMkdir := os.MkdirAll(filepath.Dir(sshKnownHostsfile), 0700)
			if errMkdir != nil {
				fmt.Fprintln(os.Stderr, "Failed to create Knownhostfile directory")
				debuglog(logLevelError, "Fatal: Failed to create Knownhostfile directory:  %s", err)
				return
			}
		}
	}

	currentLogLevel = *extcapLogLevel

	if *extcapLogFile != "" {

		logfile, err := os.OpenFile(*extcapLogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to open log file")
			debuglog(logLevelError, "Fatal: Failed to open log file:  %s", err)
		}
		defer logfile.Close()

		log.SetOutput(logfile)

		debugLogEnabled = true

		debuglog(logLevelInfo, "created log file %s", *extcapLogFile)

	}

	debuglog(logLevelInfo, "fortidump build date: %s", buildDate)
	debuglog(logLevelDebug, "parsed flags: extcap-interface=%q capture=%v host=%q username=%q capture-filter=%q",
		*extcapInterface, *extcapCapture, *extcapHost, *extcapUsername, *extcapCaptureFilter)

	args := os.Args[1:]
	quotedArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if (args[i] == captureFilterFlag || args[i] == "--username" || args[i] == "--password") && i+1 < len(args) {
			quotedArgs = append(quotedArgs, args[i], `"`+args[i+1]+`"`)
			i++
		} else {
			quotedArgs = append(quotedArgs, args[i])
		}
	}
	debuglog(logLevelDebug, strings.Join(quotedArgs, " "))

	if !*extcapInterfacesArg && *extcapInterface == "" {
		fmt.Println("An interface must be provided or the selection must be displayed")
		return
	}

	if *extcapInterfacesArg {
		extcapVersion()
		extcapInterfaces()
		return
	}

	if *extcapConfigArg {
		extcapConfig()
		return
	}

	if *extcapDtls {
		fmt.Println("dlt {number=1}{name=EN10MB}{display=Ethernet}")
		return
	}

	if *extcapVersionArg != "" {
		extcapVersion()
		return
	}

	// On SIGTERM/SIGINT close the active SSH session so runSnifferCommand exits
	// via scanner EOF and all deferred cleanup (endSSHSession etc.) runs normally.
	// If no capture is running the goroutine simply returns and main() exits on its own.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		debuglog(logLevelInfo, "Received signal: %s — shutting down", sig)
		if sess := activeSession; sess != nil {
			sess.session.Close()
			sess.client.Close()
		} else {
			os.Exit(0)
		}
	}()

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
		if *extcapFifo == "" {
			fmt.Fprintln(os.Stderr, "No fifo file defined")
			debuglog(logLevelError, "Fatal: No fifo file defined")
			os.Exit(errorFifo)
		}

		err := startCaptureSession(extcapFifo, extcapUsername, extcapPassword, extcapHost, extcapPort, extcapCaptureInterface, extcapCaptureFilter, extcapPacketLimit)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			debuglog(logLevelError, "Fatal: %s", err)
			os.Exit(errorDelay)
		}

	}

}

func checkKnownHosts() (ssh.HostKeyCallback, error) {
	f, err := os.OpenFile(sshKnownHostsfile, os.O_CREATE, 0600)
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

	f, fErr := os.OpenFile(sshKnownHostsfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if fErr != nil {
		return fErr
	}
	defer f.Close()

	knownHostsEntry := knownhosts.Normalize(remote.String())
	_, fileErr := f.WriteString(knownhosts.Line([]string{knownHostsEntry}, pubKey) + "\n")
	return fileErr
}

func newSSHSession(username *string, password *string, hostname *string, port *int) (*sshShell, error) {

	var (
		keyErr *knownhosts.KeyError
	)

	debuglog(logLevelDebug, "newSSHSession()")

	sshShellSession := sshShell{}

	authmethod := []ssh.AuthMethod{}

	if agentClient, cleanup, err := getAgentAuthSigners(); err != nil {
		debuglog(logLevelInfo, "SSH agent not available: %s", err)
	} else {
		debuglog(logLevelInfo, "SSH agent available, adding as auth method")
		authmethod = append(authmethod, ssh.PublicKeysCallback(agentClient.Signers))
		defer cleanup()
	}

	if *password != "" {
		authmethod = append(authmethod, ssh.Password(*password))
	}

	if len(authmethod) == 0 {
		return nil, fmt.Errorf("no authentication method available: provide a password or configure an SSH agent")
	}

	config := &ssh.ClientConfig{
		User: *username,
		Auth: authmethod,
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			kh, kHErr := checkKnownHosts()

			if kHErr != nil {
				return kHErr
			}

			hErr := kh(host, remote, pubKey)

			if errors.As(hErr, &keyErr) && len(keyErr.Want) > 0 {
				fmt.Fprintf(os.Stderr, "Host key mismatch for %s: the key presented by the FortiGate does not match the entry in known_hosts.\nTo fix this, remove the old entry: ssh-keygen -R %s\n", host, host)
				debuglog(logLevelError, "Host key mismatch for %s", host)
				return keyErr
			} else if errors.As(hErr, &keyErr) && len(keyErr.Want) == 0 {
				debuglog(logLevelInfo, "%s is not trusted, adding key to known_hosts file.", host)
				return addHostKey(host, remote, pubKey)
			}
			debuglog(logLevelInfo, "Public key found for %s in trusted hosts", host)
			return nil
		}),
		// Include ssh-rsa for compatibility with older FortiOS versions (< 7.4)
		// that do not advertise ed25519 or ECDSA. rsa-sha2-* variants are
		// preferred over the legacy ssh-rsa (SHA-1) when both sides support them.
		HostKeyAlgorithms: []string{"ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"},
		Timeout:           15 * time.Second,
	}

	client, err := ssh.Dial("tcp", *hostname+":"+strconv.Itoa(*port), config)
	if err != nil {
		debuglog(logLevelError, "Dial error: %s", err)
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("authentication failed: incorrect password or SSH agent has no valid key for this host")
		}
		if strings.Contains(err.Error(), "Too many authentication failures") {
			return nil, fmt.Errorf("authentication failed: too many failed attempts, the host may have blocked further logins")
		}
		if strings.Contains(err.Error(), "i/o timeout") {
			return nil, fmt.Errorf("connection timed out: verify the FortiGate address and SSH port are correct and reachable")
		}
		if strings.Contains(err.Error(), "no route to host") {
			return nil, fmt.Errorf("no route to host: verify the FortiGate address is correct and the host is reachable")
		}
		if strings.Contains(err.Error(), "EOF") {
			return nil, fmt.Errorf("connection closed unexpectedly: the FortiGate terminated the connection during handshake — a common cause is a trusted host restriction on the admin account")
		}
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	sshShellSession.client = client
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

	// Create the shared scanner once here so that runSingleCommand and
	// runSnifferCommand all read from the same bufio buffer. Creating
	// separate readers/scanners for the same io.Reader causes each one to
	// pre-fetch bytes that the other will never see.
	sshShellSession.scanner = bufio.NewScanner(sshShellSession.bufferOut)
	// Increase the per-line buffer beyond the default 64 KB to handle long
	// banners or error messages without hitting bufio.ErrTooLong.
	sshShellSession.scanner.Buffer(make([]byte, maxLineBufferSize), maxLineBufferSize)

	// Retrieve Shell prompt — if FortiGate closes the connection immediately
	// (e.g. user has no CLI access rights) Scan() returns false with no data.
	// Guard with a timeout so we don't hang forever on an unresponsive host.
	const promptTimeout = 15 * time.Second
	promptTimedOut := make(chan struct{})
	promptTimer := time.AfterFunc(promptTimeout, func() {
		debuglog(logLevelWarn, "newSSHSession: no shell prompt after %s, closing session", promptTimeout)
		close(promptTimedOut)
		sshShellSession.session.Close()
	})
	defer promptTimer.Stop()

	// Best-effort nudge to elicit the prompt; ignore the write error since
	// a failure here will surface immediately via scanner.Scan() returning false.
	sshShellSession.bufferIn.Write([]byte("\n")) //nolint:errcheck

	if !sshShellSession.scanner.Scan() {
		select {
		case <-promptTimedOut:
			return nil, fmt.Errorf("timed out after %s waiting for shell prompt", promptTimeout)
		default:
		}
		scanErr := sshShellSession.scanner.Err()
		if scanErr != nil {
			debuglog(logLevelError, "failed to read shell prompt: %s", scanErr)
			return nil, fmt.Errorf("failed to read shell prompt: %s", scanErr)
		}
		return nil, fmt.Errorf("FortiGate closed the connection without a shell prompt - verify the user account has CLI access permissions")
	}

	return &sshShellSession, nil

}

func endSSHSession(sshShellSession *sshShell) {
	debuglog(logLevelDebug, "endSSHSession()")
	sshShellSession.session.Close()
	sshShellSession.client.Close()
}

func runSingleCommand(sshShellSession *sshShell, cmd string) (string, error) {
	debuglog(logLevelDebug, "runSingleCommand()")

	// Close the session if no response arrives within the timeout. This
	// unblocks scanner.Scan() with EOF so the function returns rather than
	// hanging indefinitely on a silent connection drop or stuck FortiGate.
	const cmdTimeout = 30 * time.Second
	timedOut := make(chan struct{})
	timer := time.AfterFunc(cmdTimeout, func() {
		debuglog(logLevelWarn, "runSingleCommand: no response for %s, closing session", cmdTimeout)
		close(timedOut)
		sshShellSession.session.Close()
	})
	defer timer.Stop()

	var lineBuffer strings.Builder
	if _, err := sshShellSession.bufferIn.Write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	for sshShellSession.scanner.Scan() {
		line := sshShellSession.scanner.Text()
		lineBuffer.WriteString(line + "\n")
		debuglog(logLevelDebug, "%s", line)
		// FortiGate terminates command output with a blank line before the prompt.
		// bufio.Scanner strips \r from \r\n, so the blank line arrives as "".
		if commandPromptRe.MatchString(line) {
			break
		}
	}

	select {
	case <-timedOut:
		return "", fmt.Errorf("runSingleCommand: timed out after %s waiting for response to %q", cmdTimeout, cmd)
	default:
	}
	if err := sshShellSession.scanner.Err(); err != nil {
		return "", err
	}

	debuglog(logLevelDebug, "runSingleCommand() ended")
	return lineBuffer.String(), nil
}

// Run sniffer command. Returns when the packet limit is reached, the pipe is
// closed by Wireshark, or the SSH session ends.
// ifaceMap tracks interface name → Interface ID; new IDBs are written on first occurrence.
func runSnifferCommand(sshShellSession *sshShell, cmd string, pcapfile *os.File, packetlimit int, ifaceMap map[string]int) error {

	debuglog(logLevelDebug, "runSnifferCommand()")

	captureStartTimestamp = time.Now().Unix()

	// Use strings.Builder to accumulate SSH output. Appending to a plain
	// string with += copies the entire buffer on every line (O(n²) total).
	// Builder uses amortized O(1) appends; we materialise a string only at
	// blank lines when a packet block may be complete.
	var buf strings.Builder

	if _, err := sshShellSession.bufferIn.Write([]byte(cmd + "\n")); err != nil {
		return fmt.Errorf("failed to send sniffer command: %w", err)
	}

	packetCount := 0
	for sshShellSession.scanner.Scan() {
		line := sshShellSession.scanner.Text()
		buf.WriteString(line)
		buf.WriteByte('\n')
		debuglog(logLevelDebug, "SSH: %s", line)

		// Check for sniffer startup errors on the current line only; these
		// appear in the first few lines before any packet data arrives.
		if packetCount == 0 && pcapErrorRe.MatchString(line) {
			return fmt.Errorf("command line error: %s", line)
		}

		// A packet block is terminated by a blank line. Only attempt extraction
		// at that point — calling extractSinglePacket on every line is wasteful
		// and was the main source of repeated full-buffer scans.
		if strings.TrimSpace(line) == "" {
			s := buf.String()
			if packet, err := extractSinglePacket(&s); err == nil {
				ifName := packet.interfaceName
				if ifName == "" {
					ifName = "unknown"
				}
				ifID, seen := ifaceMap[ifName]
				if !seen {
					ifID = len(ifaceMap)
					if err := writeInterfaceDescriptionBlock(pcapfile, ifName); err != nil {
						debuglog(logLevelInfo, "Pipe closed writing IDB, stopping capture")
						sshShellSession.bufferIn.Write([]byte("\x03")) //nolint:errcheck — best-effort stop signal
						return nil
					}
					ifaceMap[ifName] = ifID
				}
				if err := writeEnhancedPacketBlock(pcapfile, *packet, ifID); err != nil {
					// Pipe closed by Wireshark — send Ctrl+C to stop the FortiGate sniffer.
					debuglog(logLevelInfo, "Pipe closed, stopping capture")
					sshShellSession.bufferIn.Write([]byte("\x03")) //nolint:errcheck — best-effort stop signal
					return nil
				}
				packetCount++
				debuglog(logLevelInfo, "Captured packet %d", packetCount)
				// Sync the builder back to the trimmed remainder left by extractSinglePacket.
				buf.Reset()
				buf.WriteString(s)
				if packetlimit > 0 && packetCount >= packetlimit {
					debuglog(logLevelInfo, "Packet limit %d reached, stopping capture", packetlimit)
					sshShellSession.bufferIn.Write([]byte("\x03")) //nolint:errcheck — best-effort stop signal
					return nil
				}
			}
		}

		// Guard against unbounded buffer growth from unexpected/malformed output.
		// If we exceed the limit, preserve only from the last packet header onward;
		// if no header is present at all, the buffer is pure junk and can be reset.
		if buf.Len() > maxLineBufferSize {
			s := buf.String()
			lines := strings.Split(s, "\n")
			lastHeader := -1
			for i := len(lines) - 1; i >= 0; i-- {
				if headerLineRe.MatchString(lines[i]) {
					lastHeader = i
					break
				}
			}
			if lastHeader > 0 {
				debuglog(logLevelWarn, "lineBuffer exceeded %d bytes, trimming %d leading lines", maxLineBufferSize, lastHeader)
				buf.Reset()
				buf.WriteString(strings.Join(lines[lastHeader:], "\n"))
			} else if lastHeader < 0 {
				debuglog(logLevelWarn, "lineBuffer exceeded %d bytes with no packet header, resetting", maxLineBufferSize)
				buf.Reset()
			}
			// lastHeader == 0: header already at start, nothing to trim
		}
	}

	scanErr := sshShellSession.scanner.Err()
	if scanErr != nil {
		debuglog(logLevelInfo, "Capture ended with scanner error after %d packets: %s", packetCount, scanErr)
	} else {
		debuglog(logLevelInfo, "Capture ended (SSH EOF) after %d packets", packetCount)
	}

	return scanErr
}

// validInterfaceRe matches safe FortiGate interface names (e.g. port1, any, wan1, dmz).
// Only alphanumeric characters, dots, hyphens, and underscores are allowed.
// This prevents newlines or special characters from being injected into the CLI command.
var validInterfaceRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validHostnameRe matches characters that are safe to embed inside a tcpdump filter expression.
// Valid hostnames and IP addresses (including IPv6) use only letters, digits, dots, hyphens,
// and colons. Anything else (spaces, parentheses, quotes) would break filter syntax.
var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9.:_-]+$`)

// validateCaptureInputs checks all user-supplied fields that are later embedded in the
// FortiGate sniffer command or in a tcpdump filter string. It returns an error describing
// the first invalid value it finds, so the problem is reported before any SSH connection
// is made and no commands are sent to the FortiGate.
func validateCaptureInputs(captureInterface, userFilter, hostname string) error {
	if !validInterfaceRe.MatchString(captureInterface) {
		return fmt.Errorf("invalid interface name %q: only letters, digits, '.', '-', and '_' are allowed", captureInterface)
	}
	if strings.ContainsRune(userFilter, '\'') {
		return fmt.Errorf("capture filter must not contain single quotes")
	}
	if !validHostnameRe.MatchString(hostname) {
		return fmt.Errorf("invalid FortiGate address %q: only letters, digits, '.', '-', '_', and ':' are allowed", hostname)
	}
	return nil
}

// buildEffectiveFilter returns the filter string to pass to the FortiGate sniffer.
// It automatically prepends an exclusion for the SSH management session so that
// the client↔FortiGate SSH traffic never appears in the capture. The user-supplied
// filter (if any) is appended with AND.
func buildEffectiveFilter(hostname string, port int, userFilter string) string {
	sshExclude := fmt.Sprintf("not (host %s and port %d)", hostname, port)

	// Try to resolve the local IP used to reach the FortiGate so we can build
	// a more precise bidirectional exclusion. UDP dial never sends any packets —
	// it only performs a routing-table lookup.
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", hostname, port))
	if err == nil {
		defer conn.Close()
		localIP := conn.LocalAddr().(*net.UDPAddr).IP.String()
		remoteIP := conn.RemoteAddr().(*net.UDPAddr).IP.String()
		sshExclude = fmt.Sprintf("not (host %s and host %s and port %d)", localIP, remoteIP, port)
		debuglog(logLevelInfo, "auto SSH exclusion filter: local IP %s, remote IP %s", localIP, remoteIP)
	} else {
		debuglog(logLevelWarn, "could not resolve local IP for SSH exclusion (%v), using host-only filter", err)
	}

	userFilter = strings.TrimSpace(userFilter)
	if userFilter == "" || userFilter == "none" {
		return sshExclude
	}
	return fmt.Sprintf("%s and (%s)", sshExclude, userFilter)
}

func startCaptureSession(filename *string, username *string, password *string, hostname *string, port *int, captureInterface *string, captureFilter *string, packetlimit *int) error {

	debuglog(logLevelInfo, "startCaptureSession starting")
	defer debuglog(logLevelInfo, "startCaptureSession exiting")

	if err := validateCaptureInputs(*captureInterface, *captureFilter, *hostname); err != nil {
		return err
	}

	effectiveFilter := buildEffectiveFilter(*hostname, *port, *captureFilter)
	debuglog(logLevelInfo, "effective capture filter: %s", effectiveFilter)

	debuglog(logLevelInfo, "opening pcapng file: %s", *filename)
	pcapFile, err := createPcapngFile(*filename)
	if err != nil {
		return fmt.Errorf("failed to create pcapng file: %s", err)
	}
	debuglog(logLevelInfo, "pcapng file opened successfully")

	defer pcapFile.Close()

	debuglog(logLevelInfo, "connecting SSH to %s:%d", *hostname, *port)
	sshSession, err := newSSHSession(username, password, hostname, port)
	if err != nil {
		return err
	}
	debuglog(logLevelInfo, "SSH connected")

	activeSession = sshSession
	defer func() {
		activeSession = nil
		endSSHSession(sshSession)
	}()

	var sniffCommand string
	if *packetlimit == 0 {
		sniffCommand = fmt.Sprintf(`diagnose sniffer packet %s '%s' 6`, *captureInterface, effectiveFilter)
	} else {
		sniffCommand = fmt.Sprintf(`diagnose sniffer packet %s '%s' 6 %d`, *captureInterface, effectiveFilter, *packetlimit)
	}
	debuglog(logLevelInfo, "sniffer command: %s", sniffCommand)

	statusOut, err := runSingleCommand(sshSession, "get system status")
	if err != nil {
		return err
	}
	debuglog(logLevelDebug, "get system status output: %s", statusOut)

	vdomActive := false
	for _, line := range strings.Split(statusOut, "\n") {
		if strings.Contains(line, "Virtual domain configuration:") {
			vdomActive = !strings.Contains(line, "disable")
			debuglog(logLevelInfo, "VDOM configuration line: %q (active: %v)", strings.TrimSpace(line), vdomActive)
			break
		}
	}

	if vdomActive {
		debuglog(logLevelInfo, "Multi-VDOM mode detected, looking for current VDOM")
		vdomName := ""
		for _, line := range strings.Split(statusOut, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Current virtual domain:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					vdomName = strings.TrimSpace(parts[1])
				}
				break
			}
		}
		if vdomName == "" {
			return fmt.Errorf("multi-VDOM mode is enabled but could not determine current VDOM from 'get system status'")
		}
		debuglog(logLevelInfo, "Entering VDOM: %s", vdomName)
		if _, err := runSingleCommand(sshSession, "config vdom"); err != nil {
			return err
		}
		if _, err := runSingleCommand(sshSession, fmt.Sprintf("edit %s", vdomName)); err != nil {
			return err
		}
		debuglog(logLevelInfo, "Entered VDOM %s successfully", vdomName)
	} else {
		debuglog(logLevelInfo, "Single-VDOM mode detected, skipping VDOM entry")
	}

	// Send SSH keepalives to prevent the connection from being dropped by
	// NAT/firewall during long or low-traffic captures.
	keepaliveDone := make(chan struct{})
	defer close(keepaliveDone)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sshSession.client.SendRequest("keepalive@openssh.com", true, nil)
			case <-keepaliveDone:
				return
			}
		}
	}()

	ifaceMap := map[string]int{}
	err = runSnifferCommand(sshSession, sniffCommand, pcapFile, *packetlimit, ifaceMap)
	if err != nil {
		return err
	}

	return nil
}

