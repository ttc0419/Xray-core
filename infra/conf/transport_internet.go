package conf

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

// Build implements Buildable.

type TCPConfig struct {
	AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
}

// Build implements Buildable.
func (c *TCPConfig) Build() (proto.Message, error) {
	config := new(tcp.Config)
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

// Build implements Buildable.

// Build implements Buildable.

type SplitHTTPConfig struct {
	Host                 string            `json:"host"`
	Path                 string            `json:"path"`
	Mode                 string            `json:"mode"`
	Headers              map[string]string `json:"headers"`
	XPaddingBytes        Int32Range        `json:"xPaddingBytes"`
	NoGRPCHeader         bool              `json:"noGRPCHeader"`
	NoSSEHeader          bool              `json:"noSSEHeader"`
	ScMaxEachPostBytes   Int32Range        `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs Int32Range        `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int64             `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs Int32Range        `json:"scStreamUpServerSecs"`
	Xmux                 XmuxConfig        `json:"xmux"`
	DownloadSettings     *StreamConfig     `json:"downloadSettings"`
	Extra                json.RawMessage   `json:"extra"`
}

type XmuxConfig struct {
	MaxConcurrency   Int32Range `json:"maxConcurrency"`
	MaxConnections   Int32Range `json:"maxConnections"`
	CMaxReuseTimes   Int32Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes Int32Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs Int32Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64      `json:"hKeepAlivePeriod"`
}

// Build implements Buildable.

func readFileOrString(f string, s []string) ([]byte, error) {
	if len(f) > 0 {
		return filesystem.ReadCert(f)
	}
	if len(s) > 0 {
		return []byte(strings.Join(s, "\n")), nil
	}
	return nil, errors.New("both file and bytes are empty.")
}

type TLSCertConfig struct {
	CertFile       string   `json:"certificateFile"`
	CertStr        []string `json:"certificate"`
	KeyFile        string   `json:"keyFile"`
	KeyStr         []string `json:"key"`
	Usage          string   `json:"usage"`
	OcspStapling   uint64   `json:"ocspStapling"`
	OneTimeLoading bool     `json:"oneTimeLoading"`
	BuildChain     bool     `json:"buildChain"`
}

// Build implements Buildable.
func (c *TLSCertConfig) Build() (*tls.Certificate, error) {
	certificate := new(tls.Certificate)

	cert, err := readFileOrString(c.CertFile, c.CertStr)
	if err != nil {
		return nil, errors.New("failed to parse certificate").Base(err)
	}
	certificate.Certificate = cert
	certificate.CertificatePath = c.CertFile

	if len(c.KeyFile) > 0 || len(c.KeyStr) > 0 {
		key, err := readFileOrString(c.KeyFile, c.KeyStr)
		if err != nil {
			return nil, errors.New("failed to parse key").Base(err)
		}
		certificate.Key = key
		certificate.KeyPath = c.KeyFile
	}

	switch strings.ToLower(c.Usage) {
	case "encipherment":
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	case "verify":
		certificate.Usage = tls.Certificate_AUTHORITY_VERIFY
	case "issue":
		certificate.Usage = tls.Certificate_AUTHORITY_ISSUE
	default:
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	}
	if certificate.KeyPath == "" && certificate.CertificatePath == "" {
		certificate.OneTimeLoading = true
	} else {
		certificate.OneTimeLoading = c.OneTimeLoading
	}
	certificate.OcspStapling = c.OcspStapling
	certificate.BuildChain = c.BuildChain

	return certificate, nil
}

type TLSConfig struct {
	Insecure                             bool             `json:"allowInsecure"`
	Certs                                []*TLSCertConfig `json:"certificates"`
	ServerName                           string           `json:"serverName"`
	ALPN                                 *StringList      `json:"alpn"`
	EnableSessionResumption              bool             `json:"enableSessionResumption"`
	DisableSystemRoot                    bool             `json:"disableSystemRoot"`
	MinVersion                           string           `json:"minVersion"`
	MaxVersion                           string           `json:"maxVersion"`
	CipherSuites                         string           `json:"cipherSuites"`
	Fingerprint                          string           `json:"fingerprint"`
	RejectUnknownSNI                     bool             `json:"rejectUnknownSni"`
	PinnedPeerCertificateChainSha256     *[]string        `json:"pinnedPeerCertificateChainSha256"`
	PinnedPeerCertificatePublicKeySha256 *[]string        `json:"pinnedPeerCertificatePublicKeySha256"`
	CurvePreferences                     *StringList      `json:"curvePreferences"`
	MasterKeyLog                         string           `json:"masterKeyLog"`
	ServerNameToVerify                   string           `json:"serverNameToVerify"`
	VerifyPeerCertInNames                []string         `json:"verifyPeerCertInNames"`
}

// Build implements Buildable.
func (c *TLSConfig) Build() (proto.Message, error) {
	config := new(tls.Config)
	config.Certificate = make([]*tls.Certificate, len(c.Certs))
	for idx, certConf := range c.Certs {
		cert, err := certConf.Build()
		if err != nil {
			return nil, err
		}
		config.Certificate[idx] = cert
	}
	serverName := c.ServerName
	config.AllowInsecure = c.Insecure
	if len(c.ServerName) > 0 {
		config.ServerName = serverName
	}
	if c.ALPN != nil && len(*c.ALPN) > 0 {
		config.NextProtocol = []string(*c.ALPN)
	}
	if len(config.NextProtocol) > 1 {
		for _, p := range config.NextProtocol {
			if tcp.IsFromMitm(p) {
				return nil, errors.New(`only one element is allowed in "alpn" when using "fromMitm" in it`)
			}
		}
	}
	if c.CurvePreferences != nil && len(*c.CurvePreferences) > 0 {
		config.CurvePreferences = []string(*c.CurvePreferences)
	}
	config.EnableSessionResumption = c.EnableSessionResumption
	config.DisableSystemRoot = c.DisableSystemRoot
	config.MinVersion = c.MinVersion
	config.MaxVersion = c.MaxVersion
	config.CipherSuites = c.CipherSuites
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint != "unsafe" && tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, errors.New(`unknown "fingerprint": `, config.Fingerprint)
	}
	config.RejectUnknownSni = c.RejectUnknownSNI

	if c.PinnedPeerCertificateChainSha256 != nil {
		config.PinnedPeerCertificateChainSha256 = [][]byte{}
		for _, v := range *c.PinnedPeerCertificateChainSha256 {
			hashValue, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			config.PinnedPeerCertificateChainSha256 = append(config.PinnedPeerCertificateChainSha256, hashValue)
		}
	}

	if c.PinnedPeerCertificatePublicKeySha256 != nil {
		config.PinnedPeerCertificatePublicKeySha256 = [][]byte{}
		for _, v := range *c.PinnedPeerCertificatePublicKeySha256 {
			hashValue, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			config.PinnedPeerCertificatePublicKeySha256 = append(config.PinnedPeerCertificatePublicKeySha256, hashValue)
		}
	}

	config.MasterKeyLog = c.MasterKeyLog

	if c.ServerNameToVerify != "" {
		return nil, errors.PrintRemovedFeatureError(`"serverNameToVerify"`, `"verifyPeerCertInNames"`)
	}
	config.VerifyPeerCertInNames = c.VerifyPeerCertInNames

	return config, nil
}

type LimitFallback struct {
	AfterBytes       uint64
	BytesPerSec      uint64
	BurstBytesPerSec uint64
}

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "raw", "tcp":
		return "tcp", nil
		errors.PrintDeprecatedFeatureWarning("gRPC transport (with unnecessary costs, etc.)", "XHTTP stream-up H2")
		return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
		return "", errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
	default:
		return "", errors.New("Config: unknown transport protocol: ", p)
	}
}

type CustomSockoptConfig struct {
	Syetem  string `json:"system"`
	Network string `json:"network"`
	Level   string `json:"level"`
	Opt     string `json:"opt"`
	Value   string `json:"value"`
	Type    string `json:"type"`
}

type HappyEyeballsConfig struct {
	PrioritizeIPv6   bool   `json:"prioritizeIPv6"`
	TryDelayMs       uint64 `json:"tryDelayMs"`
	Interleave       uint32 `json:"interleave"`
	MaxConcurrentTry uint32 `json:"maxConcurrentTry"`
}

func (h *HappyEyeballsConfig) UnmarshalJSON(data []byte) error {
	var innerHappyEyeballsConfig = struct {
		PrioritizeIPv6   bool   `json:"prioritizeIPv6"`
		TryDelayMs       uint64 `json:"tryDelayMs"`
		Interleave       uint32 `json:"interleave"`
		MaxConcurrentTry uint32 `json:"maxConcurrentTry"`
	}{PrioritizeIPv6: false, Interleave: 1, TryDelayMs: 0, MaxConcurrentTry: 4}
	if err := json.Unmarshal(data, &innerHappyEyeballsConfig); err != nil {
		return err
	}
	h.PrioritizeIPv6 = innerHappyEyeballsConfig.PrioritizeIPv6
	h.TryDelayMs = innerHappyEyeballsConfig.TryDelayMs
	h.Interleave = innerHappyEyeballsConfig.Interleave
	h.MaxConcurrentTry = innerHappyEyeballsConfig.MaxConcurrentTry
	return nil
}

type SocketConfig struct {
	Mark                  int32                  `json:"mark"`
	TFO                   interface{}            `json:"tcpFastOpen"`
	TProxy                string                 `json:"tproxy"`
	AcceptProxyProtocol   bool                   `json:"acceptProxyProtocol"`
	DomainStrategy        string                 `json:"domainStrategy"`
	DialerProxy           string                 `json:"dialerProxy"`
	TCPKeepAliveInterval  int32                  `json:"tcpKeepAliveInterval"`
	TCPKeepAliveIdle      int32                  `json:"tcpKeepAliveIdle"`
	TCPCongestion         string                 `json:"tcpCongestion"`
	TCPWindowClamp        int32                  `json:"tcpWindowClamp"`
	TCPMaxSeg             int32                  `json:"tcpMaxSeg"`
	Penetrate             bool                   `json:"penetrate"`
	TCPUserTimeout        int32                  `json:"tcpUserTimeout"`
	V6only                bool                   `json:"v6only"`
	Interface             string                 `json:"interface"`
	TcpMptcp              bool                   `json:"tcpMptcp"`
	CustomSockopt         []*CustomSockoptConfig `json:"customSockopt"`
	AddressPortStrategy   string                 `json:"addressPortStrategy"`
	HappyEyeballsSettings *HappyEyeballsConfig   `json:"happyEyeballs"`
}

// Build implements Buildable.
func (c *SocketConfig) Build() (*internet.SocketConfig, error) {
	tfo := int32(0) // don't invoke setsockopt() for TFO
	if c.TFO != nil {
		switch v := c.TFO.(type) {
		case bool:
			if v {
				tfo = 256
			} else {
				tfo = -1 // TFO need to be disabled
			}
		case float64:
			tfo = int32(math.Min(v, math.MaxInt32))
		default:
			return nil, errors.New("tcpFastOpen: only boolean and integer value is acceptable")
		}
	}
	var tproxy internet.SocketConfig_TProxyMode
	switch strings.ToLower(c.TProxy) {
	case "tproxy":
		tproxy = internet.SocketConfig_TProxy
	case "redirect":
		tproxy = internet.SocketConfig_Redirect
	default:
		tproxy = internet.SocketConfig_Off
	}

	dStrategy := internet.DomainStrategy_AS_IS
	switch strings.ToLower(c.DomainStrategy) {
	case "asis", "":
		dStrategy = internet.DomainStrategy_AS_IS
	case "useip":
		dStrategy = internet.DomainStrategy_USE_IP
	case "useipv4":
		dStrategy = internet.DomainStrategy_USE_IP4
	case "useipv6":
		dStrategy = internet.DomainStrategy_USE_IP6
	case "useipv4v6":
		dStrategy = internet.DomainStrategy_USE_IP46
	case "useipv6v4":
		dStrategy = internet.DomainStrategy_USE_IP64
	case "forceip":
		dStrategy = internet.DomainStrategy_FORCE_IP
	case "forceipv4":
		dStrategy = internet.DomainStrategy_FORCE_IP4
	case "forceipv6":
		dStrategy = internet.DomainStrategy_FORCE_IP6
	case "forceipv4v6":
		dStrategy = internet.DomainStrategy_FORCE_IP46
	case "forceipv6v4":
		dStrategy = internet.DomainStrategy_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", c.DomainStrategy)
	}

	var customSockopts []*internet.CustomSockopt

	for _, copt := range c.CustomSockopt {
		customSockopt := &internet.CustomSockopt{
			System:  copt.Syetem,
			Network: copt.Network,
			Level:   copt.Level,
			Opt:     copt.Opt,
			Value:   copt.Value,
			Type:    copt.Type,
		}
		customSockopts = append(customSockopts, customSockopt)
	}

	addressPortStrategy := internet.AddressPortStrategy_None
	switch strings.ToLower(c.AddressPortStrategy) {
	case "none", "":
		addressPortStrategy = internet.AddressPortStrategy_None
	case "srvportonly":
		addressPortStrategy = internet.AddressPortStrategy_SrvPortOnly
	case "srvaddressonly":
		addressPortStrategy = internet.AddressPortStrategy_SrvAddressOnly
	case "srvportandaddress":
		addressPortStrategy = internet.AddressPortStrategy_SrvPortAndAddress
	case "txtportonly":
		addressPortStrategy = internet.AddressPortStrategy_TxtPortOnly
	case "txtaddressonly":
		addressPortStrategy = internet.AddressPortStrategy_TxtAddressOnly
	case "txtportandaddress":
		addressPortStrategy = internet.AddressPortStrategy_TxtPortAndAddress
	default:
		return nil, errors.New("unsupported address and port strategy: ", c.AddressPortStrategy)
	}

	var happyEyeballs = &internet.HappyEyeballsConfig{Interleave: 1, PrioritizeIpv6: false, TryDelayMs: 0, MaxConcurrentTry: 4}
	if c.HappyEyeballsSettings != nil {
		happyEyeballs.PrioritizeIpv6 = c.HappyEyeballsSettings.PrioritizeIPv6
		happyEyeballs.Interleave = c.HappyEyeballsSettings.Interleave
		happyEyeballs.TryDelayMs = c.HappyEyeballsSettings.TryDelayMs
		happyEyeballs.MaxConcurrentTry = c.HappyEyeballsSettings.MaxConcurrentTry
	}

	return &internet.SocketConfig{
		Mark:                 c.Mark,
		Tfo:                  tfo,
		Tproxy:               tproxy,
		DomainStrategy:       dStrategy,
		AcceptProxyProtocol:  c.AcceptProxyProtocol,
		DialerProxy:          c.DialerProxy,
		TcpKeepAliveInterval: c.TCPKeepAliveInterval,
		TcpKeepAliveIdle:     c.TCPKeepAliveIdle,
		TcpCongestion:        c.TCPCongestion,
		TcpWindowClamp:       c.TCPWindowClamp,
		TcpMaxSeg:            c.TCPMaxSeg,
		Penetrate:            c.Penetrate,
		TcpUserTimeout:       c.TCPUserTimeout,
		V6Only:               c.V6only,
		Interface:            c.Interface,
		TcpMptcp:             c.TcpMptcp,
		CustomSockopt:        customSockopts,
		AddressPortStrategy:  addressPortStrategy,
		HappyEyeballs:        happyEyeballs,
	}, nil
}

type StreamConfig struct {
	Address        *Address           `json:"address"`
	Port           uint16             `json:"port"`
	Network        *TransportProtocol `json:"network"`
	Security       string             `json:"security"`
	TLSSettings    *TLSConfig         `json:"tlsSettings"`
	RAWSettings    *TCPConfig         `json:"rawSettings"`
	TCPSettings    *TCPConfig         `json:"tcpSettings"`
	SocketSettings *SocketConfig      `json:"sockopt"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		Port:         uint32(c.Port),
		ProtocolName: "tcp",
	}
	if c.Address != nil {
		config.Address = c.Address.Build()
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}
	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, errors.PrintRemovedFeatureError(`Legacy XTLS`, `xtls-rprx-vision with TLS or REALITY`)
	default:
		return nil, errors.New(`Unknown security "` + c.Security + `".`)
	}
	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build RAW config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}
	return config, nil
}

type ProxyConfig struct {
	Tag string `json:"tag"`

	// TransportLayerProxy: For compatibility.
	TransportLayerProxy bool `json:"transportLayer"`
}

// Build implements Buildable.
func (v *ProxyConfig) Build() (*internet.ProxyConfig, error) {
	if v.Tag == "" {
		return nil, errors.New("Proxy tag is not set.")
	}
	return &internet.ProxyConfig{
		Tag:                 v.Tag,
		TransportLayerProxy: v.TransportLayerProxy,
	}, nil
}
