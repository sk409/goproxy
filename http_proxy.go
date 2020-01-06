package goproxy

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"time"
)

var certificates = map[string]*tls.Certificate{}

type certificateAuthority struct {
	certificate *x509.Certificate
	privateKey  crypto.PrivateKey
}

type Hooks struct {
	Request  func(*http.Request)
	Response func(*http.Response)
}

type HTTPProxy struct {
	Hooks        *Hooks
	transport    *http.Transport
	ca           *certificateAuthority
	decryptHTTPS bool
}

func NewHTTPProxy(certfile, keyfile string) (*HTTPProxy, error) {
	p := HTTPProxy{
		Hooks:     &Hooks{},
		transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: http.ProxyFromEnvironment},
	}
	if len(certfile) != 0 && len(keyfile) != 0 {
		ca, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			return nil, err
		}
		x509certificate, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return nil, err
		}
		p.ca = &certificateAuthority{certificate: x509certificate, privateKey: ca.PrivateKey}
		p.decryptHTTPS = true
	}
	return &p, nil
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.Hooks.Request != nil {
		p.Hooks.Request(r)
	}
	if r.Method == http.MethodConnect {
		if p.decryptHTTPS {
			p.transportRequestHTTPS(w, r)
		} else {
			p.relayRequestHTTPS(w, r)
		}
		return
	}
	p.transportRequestHTTP(w, r)
}

func (p *HTTPProxy) transportRequestHTTP(w http.ResponseWriter, r *http.Request) error {
	p.removeProxyHeaders(r)
	serverResponse, err := p.transport.RoundTrip(r)
	if err != nil {
		return err
		// log.Printf("error read response %v %v", r.URL.Host, err.Error())
		// if serverResponse == nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }
	}
	defer serverResponse.Body.Close()
	if p.Hooks.Response != nil {
		p.Hooks.Response(serverResponse)
	}
	dest := w.Header()
	for key, values := range serverResponse.Header {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
	w.WriteHeader(serverResponse.StatusCode)
	_, err = io.Copy(w, serverResponse.Body)
	if err != nil {
		return err
	}
	return nil
}

func (p *HTTPProxy) transportRequestHTTPS(w http.ResponseWriter, r *http.Request) error {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("httpserver does not suppert hijacking")
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return err
	}
	clientConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	go func() {
		tlsConfig := tls.Config{InsecureSkipVerify: true}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			return
		}
		certificate := certificates[host]
		if certificate == nil {
			now := time.Now()
			start := now.Add(-time.Minute)
			end := now.Add(30 * 3600 * time.Hour)
			h := sha1.New()
			h.Write([]byte(host))
			randomBytes := make([]byte, 256)
			mrand.Read(randomBytes)
			h.Write(randomBytes)
			binary.Write(h, binary.BigEndian, start)
			binary.Write(h, binary.BigEndian, end)
			hash := h.Sum(nil)
			serialNumber := big.Int{}
			serialNumber.SetBytes(hash)
			serverCertificateTemplate := x509.Certificate{
				SignatureAlgorithm:    p.ca.certificate.SignatureAlgorithm,
				SerialNumber:          &serialNumber,
				Issuer:                p.ca.certificate.Subject,
				Subject:               pkix.Name{Organization: []string{"DAST"}, CommonName: host},
				NotBefore:             start,
				NotAfter:              end,
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  false,
				MaxPathLen:            0,
				MaxPathLenZero:        true,
				DNSNames:              []string{host},
			}
			derBytes, err := x509.CreateCertificate(rand.Reader, &serverCertificateTemplate, p.ca.certificate, p.ca.certificate.PublicKey, p.ca.privateKey)
			if err != nil {
				return
			}
			certificate = &tls.Certificate{
				Certificate: [][]byte{derBytes, p.ca.certificate.Raw},
				PrivateKey:  p.ca.privateKey,
			}
			certificates[host] = certificate
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *certificate)
		tlsConn := tls.Server(clientConn, &tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			return
		}
		defer tlsConn.Close()
		tlsIn := bufio.NewReader(tlsConn)
		for {
			_, err := tlsIn.Peek(1)
			if err == io.EOF {
				break
			}
			request, err := http.ReadRequest(tlsIn)
			if err != nil {
				if err == io.EOF {
					break
				}
			}
			request.URL.Scheme = "https"
			request.URL.Host = r.Host
			request.RequestURI = request.URL.String()
			request.RemoteAddr = r.RemoteAddr
			response, err := p.transport.RoundTrip(request)
			if err != nil {
				return
			}
			if p.Hooks.Response != nil {
				p.Hooks.Response(response)
			}
			response.Write(tlsConn)
		}
		return
	}()
	return nil
}

func (p *HTTPProxy) relayRequestHTTPS(w http.ResponseWriter, r *http.Request) {
	serverConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		panic("Cannot hijack connection: " + err.Error())
	}
	clientConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	transfer := func(dest io.WriteCloser, source io.ReadCloser) {
		defer dest.Close()
		defer source.Close()
		io.Copy(dest, source)
	}
	go transfer(serverConn, clientConn)
	go transfer(clientConn, serverConn)
}

func (p *HTTPProxy) removeProxyHeaders(r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")
}
