package wireguard_admin_service

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const wireguardParamsFile = "/etc/wireguard/params"

// AddUser adds new wireguard user.
func AddUser(clientName string) error {
	params, err := godotenv.Read(wireguardParamsFile)
	if err != nil {
		return fmt.Errorf("error loading .env file: %w", err)
	}

	if err = validateClientName(clientName, params["SERVER_WG_NIC"]); err != nil {
		return err
	}

	ipv4s, ipv6s, err := getExistingIPs(params["SERVER_WG_NIC"])
	if err != nil {
		return fmt.Errorf("failed to get existing IPs: %w", err)
	}

	baseIPv4 := getBaseIP(params["SERVER_WG_IPV4"], ".")

	lastOctet, err := generateRandomOctet()
	if err != nil {
		return fmt.Errorf("failed to generate random octet: %w", err)
	}
	var clientIPv4 string
	for {
		clientIPv4 = fmt.Sprintf("%s.%d", baseIPv4, lastOctet)
		_, ok := ipv4s[clientIPv4+"/32"]
		if !ok {
			break
		}
	}

	baseIPv6 := getBaseIP(params["SERVER_WG_IPV6"], "::")

	var clientIPv6 string
	for {
		clientIPv6 = fmt.Sprintf("%s::%d", baseIPv6, lastOctet)
		_, ok := ipv6s[clientIPv6+"/128"]
		if !ok {
			break
		}
	}

	clientPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}
	clientPubKey := clientPrivKey.PublicKey()

	clientPreSharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}

	endpoint := fmt.Sprintf("%s:%s", params["SERVER_PUB_IP"], params["SERVER_PORT"])

	clientConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s,%s
DNS = %s,%s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s
`, clientPrivKey, clientIPv4, clientIPv6, params["CLIENT_DNS_1"], params["CLIENT_DNS_2"],
		params["SERVER_PUB_KEY"], clientPreSharedKey, endpoint, params["ALLOWED_IPS"])

	if err = os.WriteFile(fmt.Sprintf("configs/client-%s.conf", clientName), []byte(clientConfig), 0600); err != nil {
		return fmt.Errorf("failed to write client config: %w", err)
	}

	err = generateQRCode(clientConfig, clientName)
	if err != nil {
		return fmt.Errorf("failed to generate QR Code: %w", err)
	}

	peer := fmt.Sprintf(`
### Client %s
[Peer]
PublicKey = %s
PresharedKey =%s
AllowedIPs = %s/32,%s/128
`, clientName, clientPubKey, clientPreSharedKey, clientIPv4, clientIPv6)

	err = appendToFile("/etc/wireguard/wg0.conf", peer)
	if err != nil {
		return fmt.Errorf("failed to append to file: %w", err)
	}

	return syncWireGuardConfig(params["SERVER_WG_NIC"])
}

// validateClientName checks if the client name is valid and doesn't already exist in the file.
func validateClientName(clientName, serverWgNic string) error {
	validNamePattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validNamePattern.MatchString(clientName) {
		return errors.New("invalid client name: only alphanumeric characters, underscores, and hyphens are allowed")
	}
	if len(clientName) >= 16 {
		return errors.New("client name must be less than 16 characters")
	}

	// Check if the client name already exists in the configuration file
	filePath := fmt.Sprintf("/etc/wireguard/%s.conf", serverWgNic)
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("unable to open configuration file: %w", err)
	}
	defer file.Close()

	clientExistsPattern := fmt.Sprintf("### Client %s", clientName)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == clientExistsPattern {
			return errors.New("a client with the specified name already exists, please choose another name")
		}
	}

	if scanner.Err() != nil {
		return fmt.Errorf("error reading configuration file: %w", err)
	}

	return nil
}

func getExistingIPs(deviceName string) (ipv4s, ipv6s map[string]string, err error) {
	client, err := wgctrl.New()
	if err != nil {
		return
	}
	defer client.Close()

	device, err := client.Device(deviceName)
	if err != nil {
		return
	}

	ipv4s = make(map[string]string)
	ipv6s = make(map[string]string)
	for _, peer := range device.Peers {
		for _, ip := range peer.AllowedIPs {
			if ip.IP.To4() != nil {
				ipv4s[ip.String()] = ""
			} else if ip.IP.To16() != nil {
				ipv6s[ip.String()] = ""
			}
		}
	}

	return
}

func getBaseIP(ipStr, separator string) string {
	parts := strings.Split(ipStr, separator)

	parts = parts[:len(parts)-1]
	// Join the parts back together to form the base IP
	baseIP := strings.Join(parts, separator)
	return baseIP
}

func generateRandomOctet() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(254))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 1, nil
}

func appendToFile(filePath, content string) error {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	return err
}

func generateQRCode(clientConfig, clientName string) error {
	qrFilePath := fmt.Sprintf("qr-codes/%s-client-qr.png", clientName)
	err := qrcode.WriteFile(clientConfig, qrcode.Medium, 256, qrFilePath)

	return err
}

func runCommand(command string, args []string, outputFile string) error {
	cmd := exec.Command(command, args...)

	if outputFile != "" {
		out, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer out.Close()
		cmd.Stdout = out
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run command '%s': %w", command, err)
	}

	return nil
}

// syncWireGuardConfig handles the entire process of stripping the configuration,
// syncing it with the WireGuard device, and cleaning up the temporary file.
func syncWireGuardConfig(serverWgNic string) error {
	tempFile := "/tmp/wg-stripped.conf"

	if err := runCommand("wg-quick", []string{"strip", serverWgNic}, tempFile); err != nil {
		return fmt.Errorf("error stripping configuration: %w", err)
	}

	if err := runCommand("wg", []string{"syncconf", serverWgNic, tempFile}, ""); err != nil {
		return fmt.Errorf("error syncing configuration: %w", err)
	}

	if err := runCommand("rm", []string{tempFile}, ""); err != nil {
		return fmt.Errorf("error removing temp file: %w", err)
	}

	return nil
}

func EnsureWireguardInstallation() error {
	if _, err := os.Stat(wireguardParamsFile); err == nil {
		return nil
	}

	if err := os.MkdirAll("/etc/wireguard", 0600); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	serverPrivKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}
	serverPubKey := serverPrivKey.PublicKey()

	serverPublicIP, err := getServerPubIP()
	if err != nil {
		return fmt.Errorf("failed to get server public IP: %w", err)
	}

	pubNIC, err := getDefaultNetworkInterface()
	if err != nil {
		return fmt.Errorf("failed to get default network interface: %w", err)
	}

	serverPort, err := getRandomPort()
	if err != nil {
		return fmt.Errorf("failed to get server port: %w", err)
	}

	_, err = exec.LookPath("wg")
	if err != nil {
		_ = runCommand("apt-get", []string{"update"}, "")
		if err = runCommand("apt-get", []string{"install", "-y", "wireguard", "iptables"}, ""); err != nil {
			return fmt.Errorf("failed to install wireguard: %w", err)
		}
	}

	if err := os.WriteFile(wireguardParamsFile, []byte(fmt.Sprintf(`SERVER_PUB_IP=%s
SERVER_PUB_NIC=%s
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.66.66.1
SERVER_WG_IPV6=fd42:42:42::1
SERVER_PORT=%v
SERVER_PRIV_KEY=%s
SERVER_PUB_KEY=%s
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=1.0.0.1
ALLOWED_IPS=0.0.0.0/0,::/0
`, serverPublicIP, pubNIC, serverPort, serverPrivKey, serverPubKey)), 0600); err != nil {
		return fmt.Errorf("failed to write file to %s: %w", wireguardParamsFile, err)
	}

	err = os.WriteFile("/etc/wireguard/wg0.conf", []byte(fmt.Sprintf(`[Interface]
Address = 10.66.66.1/24,fd42:42:42::1/64
ListenPort = %v
PrivateKey = %s
PostUp = iptables -I INPUT -p udp --dport %v -j ACCEPT
PostUp = iptables -I FORWARD -i %s -o wg0 -j ACCEPT
PostUp = iptables -I FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o %s -j MASQUERADE
PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o %s -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport %v -j ACCEPT
PostDown = iptables -D FORWARD -i %s -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o %s -j MASQUERADE
PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o %s -j MASQUERADE
`, serverPort, serverPrivKey, serverPort, pubNIC, pubNIC, pubNIC, serverPort, pubNIC, pubNIC, pubNIC)), 0600)
	if err != nil {
		return fmt.Errorf("failed to write file to %s: %w", wireguardParamsFile, err)
	}

	err = os.WriteFile("/etc/sysctl.d/wg.conf", []byte(`net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1`), 0600)
	if err != nil {
		return fmt.Errorf("failed to write file to /etc/sysctl.d/wg.conf: %w", err)
	}

	_ = runCommand("wg-quick", []string{"up", "/etc/wireguard/wg0.conf"}, "")

	return nil
}

func getServerPubIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error fetching network interfaces %w", err)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("error fetching addresses for interface: %w", err)
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				fmt.Println("Error parsing CIDR:", err)
				continue
			}

			if ip.IsGlobalUnicast() {
				if ip.To4() != nil {
					return ip.String(), nil
				} else if ip.To4() == nil {
					return ip.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("no IP address found")
}

// getDefaultNetworkInterface returns the name of the default network interface.
func getDefaultNetworkInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// Iterate through interfaces to find the one with an IPv4 address and set as default
	for _, iface := range interfaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Ensure it is a non-loopback IPv4 address
			if ip != nil && ip.To4() != nil {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no default network interface found")
}

func getRandomPort() (int, error) {
	const minPort = 49152
	const maxPort = 65535

	rangeSize := maxPort - minPort + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return 0, err
	}

	return int(n.Int64()) + minPort, nil
}
