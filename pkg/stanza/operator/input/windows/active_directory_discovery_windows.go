// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windows

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/sys/windows"
)

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
	ldapPath := dnsToLDAPPath(currentJoinedDomain)
	return ldapPath, nil
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
	return "LDAP://" + namingContext, nil
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
