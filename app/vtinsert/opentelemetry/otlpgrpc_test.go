package opentelemetry

import (
	"os"
	"testing"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/fs"
)

func TestNewGRPCTLSConfig(t *testing.T) {
	// Prepare test certificate files
	certFile := "test.crt"
	keyFile := "test.key"
	mustCreateFile(certFile, testCRT)
	mustCreateFile(keyFile, testPK)
	defer func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	}()

	// Happy path: verify NextProtos is set to exactly ["h2"].
	// This guard prevents accidental modification of NextProtos in the future.
	t.Run("NextProtos_h2_only", func(t *testing.T) {
		cfg, err := NewGRPCTLSConfig(certFile, keyFile, "TLS13", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
			t.Errorf("NextProtos = %v, want [h2]", cfg.NextProtos)
		}
	})

	// Error path: verify errors from GetServerTLSConfig are propagated, not swallowed.
	t.Run("Error_Propagation", func(t *testing.T) {
		_, err := NewGRPCTLSConfig("nonexistent.crt", keyFile, "TLS13", nil)
		if err == nil {
			t.Fatal("expected error for missing cert file, got nil")
		}
	})
}

const (
	testCRT = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUKm1UQfHNrw+b2T+ARui1PJexOpswDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA3MTAwMzQ1MzVaFw0yNzA3
MTAwMzQ1MzVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCgdbQ0yIk170LSfhPzrm6LuclwjxGSC31CmmF+BZUH
J19n33BrL++Rfrfz3kMr5JgfVgjeHWZ2PrLp9M9Jf9eXbcpPcPbPKm3rh1VsdNHX
o82BQ0+/pOimpWtA88A1F/XyWqC7b94531oaAOLuQzWWXeUFY4A9WlC6hkNgRj32
EIfuioEXl22pGvQqScgJOJY5nnSFLUvymKUviMTNllIQd8kdNFcz2uKKozoWl9q9
sNHxGZKTa0dfKjeok8X1pybOZK1E7JLUQBi4oPvI6YAKBFV0BTjkqu6ZBMZE1aPe
RxGdGx/fugVc2b3ON6+xfY/gaVjL1eyVG5zI6Z8xB0A3AgMBAAGjUzBRMB0GA1Ud
DgQWBBSetpW1wdKL3jKgHOj0BGX4TKRyHjAfBgNVHSMEGDAWgBSetpW1wdKL3jKg
HOj0BGX4TKRyHjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBU
gyYMzjtDq1/DF48tAnBRFomnzzUsAV2NnuMzPF6mN2kxJunyukFpCLMKYeE4d+Jn
iSDXehLY1pCzKHntTQuqavSOy4uvlboPGFbBuXuR2XYWNqH+wPRd55UtnMntAvBd
Ovec9+1MW5x0RNiiwZqZ3/oRH3CS7c3iRNMq/AXGNWomE1QXT9ujXR+86KuTBS4h
uQB6i6TyKuqzydD9nsqwuviOA7xrAthw6cqrAjgo8KBMJpFavsasnd/cZ+8YQqOW
fTEsNj4PXjYkQP6z6FW/pbNeJLkjuSIwmcs1m5t2bV5oF2kpx+NyqGW0TcYaw3KY
sWswtTQyQldPeQIkIz1p
-----END CERTIFICATE-----`
	testPK = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgdbQ0yIk170LS
fhPzrm6LuclwjxGSC31CmmF+BZUHJ19n33BrL++Rfrfz3kMr5JgfVgjeHWZ2PrLp
9M9Jf9eXbcpPcPbPKm3rh1VsdNHXo82BQ0+/pOimpWtA88A1F/XyWqC7b94531oa
AOLuQzWWXeUFY4A9WlC6hkNgRj32EIfuioEXl22pGvQqScgJOJY5nnSFLUvymKUv
iMTNllIQd8kdNFcz2uKKozoWl9q9sNHxGZKTa0dfKjeok8X1pybOZK1E7JLUQBi4
oPvI6YAKBFV0BTjkqu6ZBMZE1aPeRxGdGx/fugVc2b3ON6+xfY/gaVjL1eyVG5zI
6Z8xB0A3AgMBAAECggEADG12rWc3YqiAcz9q5ILcMqaLM1RkBtIspkBruvAhaIzu
8Y4Xgw29jyC9Nujo00OgrpNMxjCJE4Zr9/0geC+rxHbZ5kjjAgzmDN8N9C5LZFle
R3EtrN5PsJHQ7+u7tWurflTw7E4lQYk1eBxydwQDPf1RXsH5QtyLB8ScqkkLxSdy
LztMqwu6w9c0TEuzkKMaVgz0xSj2+FLN6yzAQQJUKRCPLff+uKlQx769JA9sji1C
wxcbSJZXdy0EwkGW/4EjGEPxGxZKunSrlem5A5/RPsfFtDo0DWRzZNCt022TVD/X
QesFDt6iZXpo9QUmSPiw25pZn4QD/7bNqePyLxNhLQKBgQDBc+I5WXceSNl5tXOL
UTLkSJaG0R3tBdtQY+Rc0KEQsHi0we968O0BbdFgvdwJw3YWzqm3QtAflgn4GP4X
1pg7CiCy+8cQFY2TShDJpQ//Z0GwDNUeb9I8cevIsONxRsxVphXovRN7/UFc+Hpi
Gnibm/lC9w4F8nXouBCvFzQX3QKBgQDUVv39xUjlBY7qFgTayDY7VfH5HNXgbW+f
sU56EqHtl0VDsDwgI5+91q4uK/X6m0T7FdW1Ua8iKUf+keDzOJR8HeMF01OzpWJR
p/Wqns1P60KGZv/OWn52J7uYMIslU+VyMvCn58QrrRtchJE3QgVKZUcC5kqpWFul
SXax7h6hIwKBgG+OxTlvNzsWpZsDIXOIysFMfsmWFBzYUMXGJS3E/ezi52jNoa2S
/Anj62dPdXGH7zRtzv8on15npq4Us4rJrJX3XC369at30mHKx22RK22MfRvp+oiH
0YQb6e2c3Dw5qKIHmgDR8EeDH0te2yxxuXV6974/PC3/yTD/3FcsGVVdAoGAMeSK
46ECgsWukfRAicO3cnO8WoNbAdPVAZngzbApGjGMFd6IEikstKeH39N2hb8ME09L
GsKpuwYmI3vVdnDZ+tvu5wSDy1dV5cfoYoHTzi6CQCBdhPggdNTbMGRfnZK7+/xa
Lam4n2aaYj/H+0rpAVUQvW6tJmNbjVfYqvA/hC8CgYB8gqUIhP4yz15P2936g8bS
uhNX7Msd6fwLsq/5Hn1j+7oCQ3KfvxOnFUFRDIUQvpLsa38rfn1u06gSXkSoM/3m
WN7PV6auY4J9vhiJcDHLYKWU6IiDPXa2K0EsGarWy1ncJQdpjZPT1Urft2pNF9gP
YwXfJbKUZnJlv9XplwR7Dw==
-----END PRIVATE KEY-----`
)

func mustCreateFile(path, contents string) {
	fs.MustWriteSync(path, []byte(contents))
}
