package trustscore

import (
	"log"
	"sync"

	"github.com/ip2location/ip2location-go/v9"
)

var (
	geoDB       *ip2location.DB
	asnDB       *ip2location.DB
	geoInitOnce sync.Once
)

// InitLocationIntelligence initializes BOTH the DB11 (Geo) and ASN databases.
func InitLocationIntelligence(geoPath string, asnPath string) error {
	var initErr error
	geoInitOnce.Do(func() {
		var err error

		// Load Geo DB
		geoDB, err = ip2location.OpenDB(geoPath)
		if err != nil {
			log.Printf("Failed to open Geo database at %s: %v", geoPath, err)
			initErr = err
			return
		}

		// Load ASN DB
		asnDB, err = ip2location.OpenDB(asnPath)
		if err != nil {
			log.Printf("Failed to open ASN database at %s: %v", asnPath, err)
			initErr = err
		}
	})
	return initErr
}

// CloseLocationIntelligence safely closes both databases.
func CloseLocationIntelligence() {
	if geoDB != nil {
		geoDB.Close()
	}
	if asnDB != nil {
		asnDB.Close()
	}
}

// GetASNAndRegion queries both databases to assemble the full profile.
func GetASNAndRegion(ipString string) (countryCode string, region string, asn string) {
	// 1. Fetch Geo Data
	if geoDB != nil {
		record, err := geoDB.Get_all(ipString)
		if err == nil && record.Country_short != "Invalid IP address." {
			countryCode = record.Country_short
			region = record.Region
		}
	}

	// 2. Fetch ASN Data
	if asnDB != nil {
		record, err := asnDB.Get_all(ipString)
		if err == nil && record.Asn != "Invalid IP address." {
			asn = record.Asn
		}
	}

	return countryCode, region, asn
}
