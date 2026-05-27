package trustscore

import (
	"log"
	"sync"

	"github.com/ip2location/ip2proxy-go"
)

var (
	proxyDB       *ip2proxy.DB
	proxyInitOnce sync.Once
)

// InitProxyDetection initializes the IP2Proxy database.
// This database can resolve whether an IP is a VPN, Tor node, or Datacenter.
func InitProxyDetection(dbPath string) error {
	var err error
	proxyInitOnce.Do(func() {
		proxyDB, err = ip2proxy.OpenDB(dbPath)
		if err != nil {
			log.Printf("Failed to open IP2Proxy database at %s: %v", dbPath, err)
		} else {
			log.Printf("Successfully loaded IP2Proxy database from %s", dbPath)
		}
	})
	return err
}

// CloseProxyDetection closes the IP2Proxy database.
func CloseProxyDetection() {
	if proxyDB != nil {
		proxyDB.Close()
	}
}

// EnrichIPData performs a fast local lookup to determine if the IP is Tor, VPN, or Datacenter.
func EnrichIPData(ipString string) (isTor bool, isVPN bool, isDatacenter bool) {
	if proxyDB == nil {
		return false, false, false
	}

	record, err := proxyDB.GetProxyType(ipString)
	if err != nil {
		return false, false, false
	}

	// IP2Proxy returns strings like "VPN", "TOR", "DCH" (Datacenter), "PUB" (Public Proxy), "WEB" (Web Proxy), "SES" (Search Engine Spider)
	switch record {
	case "TOR":
		isTor = true
	case "VPN":
		isVPN = true
	case "DCH": // Datacenter / Hosting
		isDatacenter = true
	case "PUB", "WEB": // Treat public/web proxies as VPN for scoring purposes
		isVPN = true
	}

	return isTor, isVPN, isDatacenter
}
