// utls-fingerprint: Connect to a target using various uTLS ClientHello profiles.
//
// Each profile impersonates a specific browser's TLS fingerprint.
// This validates whether JA3/JA4 detection rules can be evaded by TLS spoofing.
//
// Usage: utls-fingerprint <target_host:port>

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

var profiles = []struct {
	name string
	id   utls.ClientHelloID
}{
	{"Chrome 120", utls.HelloChrome_120},
	{"Firefox 120", utls.HelloFirefox_120},
	{"Safari 16.1", utls.HelloSafari_16_1},
	{"Edge 106", utls.HelloEdge_106},
	{"Go default", utls.HelloGolang},
	{"Randomized", utls.HelloRandomized},
}

func connectWithProfile(target, profileName string, helloID utls.ClientHelloID) error {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	tlsConn := utls.UClient(conn, &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
	}, helloID)

	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Send a minimal HTTP request to complete the connection
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = target
	req.Write(tlsConn)

	buf := make([]byte, 4096)
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := tlsConn.Read(buf)
	if n > 0 {
		// Just read the status line
		for i := 0; i < n && i < 100; i++ {
			if buf[i] == '\n' {
				fmt.Printf("  Response: %s\n", string(buf[:i]))
				break
			}
		}
	}

	state := tlsConn.ConnectionState()
	fmt.Printf("  TLS %s, cipher 0x%04x\n", versionName(state.Version), state.CipherSuite)
	return nil
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func main() {
	target := "172.30.0.2:8443"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	fmt.Printf("uTLS fingerprint evasion test against %s\n\n", target)

	for _, p := range profiles {
		fmt.Printf("[%s]\n", p.name)
		if err := connectWithProfile(target, p.name, p.id); err != nil {
			fmt.Printf("  ERROR: %v\n", err)
		}
		fmt.Println()
	}

	_ = io.Discard // suppress unused import
}
