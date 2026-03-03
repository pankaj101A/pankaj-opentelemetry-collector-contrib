// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os/user"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/ntlm"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// SSPINegotiator implements ldap.NTLMNegotiator using current user's SSPI credentials.
// This mirrors C++ ADsOpenObject(..., ADS_SECURE_AUTHENTICATION) with null username/password.
type SSPINegotiator struct {
	creds *sspi.Credentials   // current user creds acquired from SSPI
	ctx   *ntlm.ClientContext // NTLM client context for challenge/response
}

// Acquire current logged-on user credentials no username/password needed
func (n *SSPINegotiator) Negotiate(domain string, workstation string) ([]byte, error) {
	creds, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire current user SSPI credentials: %w", err)
	}
	n.creds = creds

	// Create NTLM client context and generate Type 1 (Negotiate) message
	ctx, negotiateMsg, err := ntlm.NewClientContext(creds)
	if err != nil {
		creds.Release()
		return nil, fmt.Errorf("failed to create NTLM client context: %w", err)
	}
	n.ctx = ctx
	return negotiateMsg, nil
}

func (n *SSPINegotiator) ChallengeResponse(challenge []byte, _ string, _ string) ([]byte, error) {
	// Process Type 2 (Challenge) from server, produce Type 3 (Authenticate) message
	authenticateMsg, err := n.ctx.Update(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to process NTLM challenge: %w", err)
	}
	return authenticateMsg, nil
}

func (n *SSPINegotiator) Release() {
	if n.ctx != nil {
		n.ctx.Release()
	}
	if n.creds != nil {
		n.creds.Release()
	}
}

// GetLDAPDomainPath discovers the root domain path of the Active Directory service.
// It first tries querying the LDAP Root DSE, then falls back to the Windows API.
// Returns a path like "LDAP://DC=example,DC=com".
func GetLDAPDomainPath() (string, error) {
	currentJoinedDomain, currentDomainError := getCurrentMachineJoinedDomain()
	if currentDomainError != nil {
		return "", fmt.Errorf("failed to get current machine joined domain: %w", currentDomainError)
	}

	fmt.Printf("current machine joined domain is %s\n", currentJoinedDomain)

	// Primary: query Root DSE with the current joined domain as the LDAP server
	path, err := getRootLDAPDomainPath(currentJoinedDomain)
	if err == nil {
		return path, nil
	}
	fmt.Printf("return current join domain path, error while getting rootDomainPath using ldap %s \n", err)
	// Fallback: current Joined Domain
	return currentJoinedDomain, nil
}

// getRootLDAPDomainPath connects to the current machine joined DC and reads
// the defaultNamingContext attribute.
func getRootLDAPDomainPath(domain string) (string, error) {
	conn, err := ldap.DialURL("ldap://" + domain)
	if err != nil {
		return "", fmt.Errorf("failed to connect to LDAP Root DSE: %w", err)
	}
	defer conn.Close()

	req := ldap.NewSearchRequest(
		"",                   // Base DN: empty string = Root DSE
		ldap.ScopeBaseObject, // Only the root entry itself
		ldap.NeverDerefAliases,
		0,     // No size limit
		0,     // No time limit
		false, // attrs only = false
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("LDAP Root DSE search failed: %w", err)
	}

	if len(res.Entries) == 0 {
		return "", fmt.Errorf("LDAP Root DSE returned no entries")
	}

	namingContext := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if namingContext == "" {
		return "", fmt.Errorf("defaultNamingContext attribute is empty")
	}

	// namingContext is already in DN format, e.g. "DC=example,DC=com"
	return dnToHostname(namingContext), nil
}

// getLDAPDomainPathFromWindowsAPI uses GetComputerNameEx to get the DNS domain
// name and converts it to an LDAP path.
func getCurrentMachineJoinedDomain() (string, error) {
	// First call to get required buffer size
	var size uint32
	err := windows.GetComputerNameEx(windows.ComputerNameDnsDomain, nil, &size)
	if err != nil && err != windows.ERROR_MORE_DATA {
		return "", fmt.Errorf("GetComputerNameEx (size query) failed: %w", err)
	}

	if size == 0 {
		return "", fmt.Errorf("computer is not joined to a domain")
	}

	buf := make([]uint16, size)
	err = windows.GetComputerNameEx(windows.ComputerNameDnsDomain, &buf[0], &size)
	if err != nil {
		return "", fmt.Errorf("GetComputerNameEx failed: %w", err)
	}

	// Decode UTF-16 to string, trimming null terminator
	dnsDomain := windows.UTF16ToString(buf[:size])
	if dnsDomain == "" {
		return "", fmt.Errorf("computer is not joined to a domain (empty DNS domain)")
	}

	return dnsDomain, nil
}

// dnsToLDAPPath converts a DNS domain name to an LDAP path.
// Example: "example.com" -> "LDAP://DC=example,DC=com"
func dnsToLDAPPath(dnsDomain string) string {
	parts := strings.Split(dnsDomain, ".")
	dcParts := make([]string, len(parts))
	for i, part := range parts {
		dcParts[i] = "DC=" + part
	}
	return "LDAP://" + strings.Join(dcParts, ",")
}

func discoverDomainControllersForJoinedDomain(logger *zap.Logger) (string, []string, error) {
	domain, err := GetLDAPDomainPath()
	if err != nil {
		return "", nil, err
	}
	logger.Info("root domain: " + domain)

	domainControllers, err := getDomainControllersForDomain(domain)
	if err != nil {
		return domain, nil, err
	}
	return domain, domainControllers, nil
}

func getDomainControllersForDomain(domain string) ([]string, error) {
	conn, err := ldap.DialURL("ldap://" + domain)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", domain, err)
	}
	defer conn.Close()

	domainDN := domainToDN(domain)

	u, _ := user.Current()
	fmt.Println("running as:", u.Username)

	negotiator := &SSPINegotiator{}
	defer negotiator.Release()

	_, err = conn.NTLMChallengeBind(&ldap.NTLMBindRequest{
		Negotiator:         negotiator,
		AllowEmptyPassword: true,
	})

	if err != nil {
		return nil, fmt.Errorf("SSPI NTLM bind failed: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		domainDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1000,  // Size limit, keeping 1000 for safety, though we expect far fewer DCs
		0,     // Time limit (0 = unlimited)
		false, // Types only
		"(&(objectClass=computer)(primaryGroupID=516))",      // LDAP filter for DCs
		[]string{"dNSHostName", "name", "distinguishedName"}, // Attributes to retrieve
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed for domain %s: %w", domain, err)
	}

	var domainControllers []string
	for _, entry := range sr.Entries {
		dc := entry.GetAttributeValue("dNSHostName")
		if dc != "" {
			domainControllers = append(domainControllers, dc)
		}
	}

	return domainControllers, nil
}

// domainToDN converts a domain name to an LDAP Distinguished Name.
// Example: "example.com" -> "DC=example,DC=com"
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dnParts := make([]string, len(parts))
	for i, part := range parts {
		dnParts[i] = "DC=" + part
	}
	return strings.Join(dnParts, ",")
}

func dnToHostname(dn string) string {
	parts := strings.Split(dn, ",")
	fmt.Printf("dn is %v and dn parts are %v\n", dn, parts)
	labels := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			labels = append(labels, p[3:])
		}
	}
	return strings.Join(labels, ".")
}

func getJoinedDomainControllersRemoteConfig(logger *zap.Logger, username string, password string) ([]RemoteConfig, error) {
	var domainControllerConfigs []RemoteConfig
	domain, domainControllers, err := discoverDomainControllersForJoinedDomain(logger)
	if err != nil {
		return nil, errors.New("failed to discover domain controllers: " + err.Error())
	}
	if len(domainControllers) == 0 {
		return nil, errors.New("no domain controllers found during discovery")
	}
	for _, dc := range domainControllers {
		config := RemoteConfig{Server: dc, Username: username, Password: password, Domain: domain}
		domainControllerConfigs = append(domainControllerConfigs, config)
	}
	logger.Info("Discovered domain controllers", zap.Int("count", len(domainControllers)))
	return domainControllerConfigs, nil
}
