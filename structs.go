package ruckus

type Options func(*Ruckus)

type LogonSessions struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	TimeZoneUtcOffset string `json:"timeZoneUtcOffset"`
}

func NewLogonSessions(username string, password string) LogonSessions {
	return LogonSessions{
		Username:          username,
		Password:          password,
		TimeZoneUtcOffset: "+08:00",
	}
}

type RuckusGeneral struct {
	TotalCount int
	HasMore    bool
	FirstIndex int
}

type RuckusError struct {
	Message   *string `json:"message,omitempty"`
	ErrorCode *int    `json:"errorCode,omitempty"`
	ErrorType *string `json:"errorType,omitempty"`
}

// Wireless Client
type Client struct {
	// MAC of the Client
	Mac string

	// IP address of the Client
	IpAddress string

	// IP V6 address of the Client
	Ipv6Address string

	HostName string
	OsType   string
	User     string
	Status   string

	// Radio inditifier
	RadioId string

	RadioMode string
	Channel   string

	// WLAN inditifier
	WlanId string

	// SSID
	Ssid string

	// SNR(dB)
	Snr string

	// RSSI(dBm)
	Rssi string

	// RX Byte Rate
	RxByteRate int

	// TX Byte Rate
	TxByteRate int

	// RX Avg Byte Rate
	RxAvgByteRate int

	// TX Avg Byte Rate
	TxAvgByteRate int

	// From client bytes
	FromClientBytes int

	// To client bytes
	ToClientBytes int

	// From client package frames
	FromClientPkts int

	// To client package frames
	ToClientPkts int

	// Connected since (in milliseconds)
	ConnectedSince int

	// VLAN id
	Vlan string

	// AP Tx Data Rate
	ToClientDroppedPkts int
}

// L2 Access Control
type L2acl struct {
	// required
	// name of the L2 Access Control
	Name string `json:"name"`

	// identifier of the L2 Access Control
	Id string `json:"id"`

	// description of the L2 Access Control
	Description string `json:"description"`

	// identifier of the zone which the L2 Access Control belongs to
	ZoneId string `json:"zoneId"`

	// required
	// either ALLOW or BLOCK
	// restriction of the L2 Access Control, ALLOW: Only allow all stations listed below, BLOCK:Only block all stations listed below
	Restriction string `json:"restriction"`

	RuleMacs []string `json:"ruleMacs"`
}

// Wireless AP Zone
type Zone struct {
	// Identifier of the zone
	Id string

	// Name of the zone
	Name string
}

// Access Point
type Ap struct {
	// Administrative state of the AP. A locked AP will not provide any WLAN services.
	AdministrativeState string

	// Identifier of the AP group to which the AP belongs. If the AP belongs to the default AP group, this property is not needed.
	ApGroupId string

	// Venue code
	AwsVenue string

	// Description of the AP
	Description string

	// GPS Source of the AP
	GpsSource string

	// Latitude coordinate (in decimal format) of the AP
	Latitude float32

	// Location of the AP. This is a free format text description that indicates the location of the AP
	Location string

	// Longitude coordinate (in decimal format) of the AP
	Longitude float32

	// required
	// MAC address of the A
	Mac string

	// Model name of the AP
	// minLength: 2
	// maxLength: 64
	// pattern: "^[!-~]((?!\$\()[ -_a-~]){0,62}[!-~]$"
	Model string

	// Name of the AP
	Name string

	// Provision checklist of the AP. This field indicates the steps that have been completed in the AP provisioning process.
	ProvisionChecklist string

	// Serial number of the AP
	Serial string

	// required
	// Identifier of the zone to which the AP belongs
	ZoneId string
}
