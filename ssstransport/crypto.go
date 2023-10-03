package ssstransport

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	tls "github.com/Danny-Dasilva/utls"
)

const (
	chrome  = "chrome"
	firefox = "firefox"
)

func getExtMap() map[string]tls.TLSExtension {
	return map[string]tls.TLSExtension{
		"0": &tls.SNIExtension{},
		"5": &tls.StatusRequestExtension{},
		// These are applied later
		// "10": &tls.SupportedCurvesExtension{...}
		// "11": &tls.SupportedPointsExtension{...}
		"13": &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},
		"16": &tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		"17": &tls.GenericExtension{Id: 17}, // status_request_v2
		"18": &tls.SCTExtension{},
		"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		"22": &tls.GenericExtension{Id: 22}, // encrypt_then_mac
		"23": &tls.UtlsExtendedMasterSecretExtension{},
		"27": &tls.CompressCertificateExtension{
			Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		},
		"28": &tls.FakeRecordSizeLimitExtension{}, // Limit: 0x4001
		"35": &tls.SessionTicketExtension{},
		"34": &tls.GenericExtension{Id: 34},
		"41": &tls.GenericExtension{Id: 41}, // FIXME pre_shared_key
		"43": &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10}},
		"44": &tls.CookieExtension{},
		"45": &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},
		"49": &tls.GenericExtension{Id: 49}, // post_handshake_auth
		"50": &tls.GenericExtension{Id: 50}, // signature_algorithms_cert
		"51": &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
			{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: tls.X25519},

			// {Group: tls.CurveP384}, known bug missing correct extensions for handshake
		}},
		"30032": &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
		"13172": &tls.NPNExtension{},
		"17513": &tls.ApplicationSettingsExtension{
			SupportedALPNList: []string{
				"h2",
			},
		},
		"65281": &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
}

type parsedJa3 struct {
	ciphers      []string
	extensions   []string
	curves       []string
	pointFormats []string
}

type errExtensionNotExist struct {
	context string
}

func (w *errExtensionNotExist) Error() string {
	return fmt.Sprintf("extension is not supported by ssstls: %s", w.context)
}

func raiseExtensionError(info string) *errExtensionNotExist {
	return &errExtensionNotExist{
		context: info,
	}
}

func parseUserAgent(userAgent string) string {
	if strings.Contains(strings.ToLower(userAgent), "firefox") {
		return firefox
	}
	return chrome
}

func parseJa3(ja3 string) parsedJa3 {
	mtrx := make([][]string, 4)
	ptr, c := 4, 0

	for i := ptr; i < len(ja3); i++ {
		if ja3[i] == '-' || ja3[i] == ',' {
			mtrx[c] = append(mtrx[c], ja3[ptr:i])
			ptr = i + 1
		}
		if ja3[i] == ',' {
			c += 1
		}
	}
	mtrx[c] = append(mtrx[c], ja3[ptr:])

	return parsedJa3{mtrx[0], mtrx[1], mtrx[2], mtrx[3]}
}

func stringToSpec(ja3 string, userAgent string) (*tls.ClientHelloSpec, error) {
	parsedUa := parseUserAgent(userAgent)
	parsedJa3 := parseJa3(ja3)

	extMap := getExtMap()

	// Parse curves
	var targetCurves []tls.CurveID
	targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER)) //append grease for Chrome browsers
	for _, c := range parsedJa3.curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// Parse point formats
	var targetPointFormats []byte
	for _, p := range parsedJa3.pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// Build extenions list
	var exts []tls.TLSExtension
	// Optionally Add Chrome Grease Extension
	if parsedUa == chrome {
		exts = append(exts, &tls.UtlsGREASEExtension{})
	}
	for _, e := range parsedJa3.extensions {
		te, ok := extMap[e]
		if !ok {
			return nil, raiseExtensionError(e)
		}
		// Optionally add Chrome Grease Extension
		if e == "21" && parsedUa == chrome {
			exts = append(exts, &tls.UtlsGREASEExtension{})
		}
		exts = append(exts, te)
	}

	// Build CipherSuites
	var suites []uint16
	// Optionally Add Chrome Grease Extension
	if parsedUa == chrome {
		suites = append(suites, tls.GREASE_PLACEHOLDER)
	}
	for _, c := range parsedJa3.ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}
	return &tls.ClientHelloSpec{
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}, nil
}
