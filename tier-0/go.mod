module waf_proxy

go 1.26.3

require (
	github.com/corazawaf/coraza-coreruleset v0.0.0-20240226094324-415b1017abdc
	github.com/corazawaf/coraza/v3 v3.7.0
	github.com/corazawaf/libinjection-go v0.3.2
	github.com/dmitryikh/leaves v0.0.0-20230708180554-25d19a787328
	github.com/redis/go-redis/v9 v9.20.0
	golang.org/x/crypto v0.52.0
	trustscore v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.18.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976 // indirect
	github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092 // indirect
	github.com/ip2location/ip2location-go/v9 v9.8.0 // indirect
	github.com/ip2location/ip2proxy-go v3.0.0+incompatible // indirect
	github.com/kaptinlin/go-i18n v0.1.4 // indirect
	github.com/kaptinlin/jsonschema v0.4.6 // indirect
	github.com/magefile/mage v1.17.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.44 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	lukechampine.com/uint128 v1.2.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace trustscore => ../trustscore

replace github.com/Abdelkader-Ammar/AI-Powered-WAF/trustscore => ../trustscore
