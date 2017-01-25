package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"time"
)

func main() {

	a := `
	//**********************************
	// Public and Private key encryption
	//**********************************`
	fmt.Println(a)
	// generate a new random publlic/private keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %s", err)
	}

	// encrypt
	plaintext := []byte("hello, I need to get encrypted")

	// use public key to encrypt
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privKey.PublicKey, plaintext)
	if err != nil {
		log.Fatalf("encrypting data: %s", err)
	}
	fmt.Printf("encrypted: %#x\n", ciphertext)

	// decrypt
	decryptedText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
	if err != nil {
		log.Fatalf("decrypt data: %s", err)
	}
	fmt.Println("decrypted: " + string(decryptedText))

	b := `
	//*******************
	// Digital Signatures
	//*******************`
	fmt.Println(b)

	hash := sha256.Sum256(plaintext)
	fmt.Printf("256 sha sum: %x\n", hash)

	//Generate signature using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Fatalf("generatting signature: %s", err)
	}
	fmt.Printf("signature: %#x\n", signature)

	// verify the signature using the public key
	verify := func(pub *rsa.PublicKey, msg, signature []byte) error {
		hash := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	}

	fmt.Printf("verify signature with a different origin plaintext %v\n", verify(&privKey.PublicKey, []byte("something different"), signature))
	fmt.Printf("verify signature with a different signature %v\n", verify(&privKey.PublicKey, plaintext, []byte("something different")))
	fmt.Printf("verify signature %v\n", verify(&privKey.PublicKey, plaintext, signature))

	c := `
	//**********************************
	// Generating x509 self-signed certs
	//**********************************`
	fmt.Println(c)

	// remember cert are just public keys with metadata
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %s", err)
	}
	rootCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("creating cert template: %s", err)
	}
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	rootCert, rootCertPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("creating cert: %s", err)
	}
	fmt.Println("certificate ↓↓↓")
	fmt.Printf("%s\n", rootCertPEM)
	fmt.Println("rootcert signature ↓↓↓")
	fmt.Printf("%#x\n", rootCert.Signature)

	d := `
	//*********************************
	// use self-signed certs for server
	//*********************************`
	fmt.Println(d)

	// PEM encode the private key
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	// create TLS cert using private key and the cert
	rootTLSCert, err := tls.X509KeyPair(rootCertPEM, rootKeyPEM)
	if err != nil {
		log.Fatalf("invalid key pair: %s", err)
	}

	// Example of a cert signed by unkown authority
	StartTestServer(rootTLSCert)

	e := `
	//**********************************
	// Getting client to trust the sever
	//**********************************`
	fmt.Println(e)

	// generate a key pair for the server
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %s\n", err)
	}
	serverCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("error generating template: %s\n", err)
	}
	serverCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	serverCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	// create a certificate which wraps the server's public key, sign it with the root private key
	// pretending rootCert belongs to CA
	_, serverCertPEM, err := CreateCert(serverCertTmpl, rootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("err creating cert: %v", err)
	}
	// provide the private key and the cert
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})
	servTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		log.Fatalf("invalid key pair: %s\n", err)
	}
	StartTrustedTestServer(servTLSCert, rootCertPEM)

	f := `
	//**********************************
	// Getting client to trust the sever
	//**********************************`
	fmt.Println(f)
	StartTrustedTestServerWithTrustedClient(servTLSCert, rootCert, rootKey, rootCertPEM)

}

func CreateCert(template, parent *x509.Certificate, pub, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	//PEM encoded cert (standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// helper func to crate cert template with a serial number and other fields
func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Ninoski, Inc."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil

}

func StartTrustedTestServerWithTrustedClient(cert tls.Certificate, rootCert *x509.Certificate, rootKey interface{}, rootCertPEM []byte) {
	// create a key-pair for the client
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %s", err)
	}
	// create a cert template for the client
	clientCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("creating cert template: %s", err)
	}
	clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	// the root cert(we are using same as sever) signs the cert by again providing its private key
	_, clientCertPEM, err := CreateCert(clientCertTmpl, rootCert, &clientKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}
	// encode and load the cert and private key for the client
	clientKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPem)
	if err != nil {
		log.Fatalf("invalid key pair: %v", err)
	}
	// create a pool of trusted certs
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCertPEM)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK!")) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // enbale clientAuth
		ClientCAs:    certPool,
	}
	s.StartTLS()
	resp, err := client.Get(s.URL)
	if err != nil {
		log.Fatalf("GET: %s\n", err)
	}
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatalf("could not dump response: %s\n", err)
	}
	fmt.Println(string(dump))
	s.Close()
}

func StartTrustedTestServer(cert tls.Certificate, rootCertPEM []byte) {
	var err error
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK!")) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s.StartTLS()
	// create a pool of trusted certs
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCertPEM)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	resp, err := client.Get(s.URL)
	if err != nil {
		log.Fatalf("GET: %s\n", err)
	}
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatalf("could not dump response: %s\n", err)
	}
	fmt.Println(string(dump))
	s.Close()
}

func StartTestServer(cert tls.Certificate) {
	var err error
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK!")) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s.StartTLS()
	_, err = http.Get(s.URL)
	if err != nil {
		fmt.Println(err)
	}
	s.Close()
}
