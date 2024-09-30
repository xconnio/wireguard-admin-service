package wireguard_admin_service

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AddUser adds new wireguard user.
func AddUser(clientName string) error {
	params, err := godotenv.Read("/etc/wireguard/params")
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
