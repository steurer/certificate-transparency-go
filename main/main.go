package main

import (
	"bufio"
	"context"
	"flag"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/klauspost/compress/zstd"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	out = flag.String("out", "ct_names.zst", "")
	url = flag.String("url", "https://ct.cloudflare.com/logs/nimbus2024/", "")
)

func main() {

	out, closeFunc, err := getFileWriter(*out, true)
	if err != nil {
		panic(err)
	}
	defer closeFunc()

	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	//
	// https://ct.googleapis.com/logs/solera2023/
	c, err := client.New(*url, hc, jsonclient.Options{UserAgent: "ct-go-sctscan/1.0"})
	if err != nil {
		panic(err)
	}
	opts := *scanner.DefaultScannerOptions()
	opts.NumWorkers = 5
	opts.ParallelFetch = 5

	s := scanner.NewScanner(c, opts)

	ctx, cncl := context.WithTimeout(context.Background(), 240*time.Second)
	defer cncl()

	nameChan := make(chan string, 1000)
	done := make(chan bool)
	go func() {
		for name := range nameChan {
			if _, err := out.Write([]byte(name + "\n")); err != nil {
				panic(err)
			}
		}
		done <- true
	}()

	now := time.Now()
	err = s.Scan(ctx, func(entry *ct.RawLogEntry) {
		if entry.Index%10000 == 0 {
			log.Printf("At %v", entry.Index)
		}

		parsedEntry, err := entry.ToLogEntry()
		if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
			log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
			return
		}

		if now.After(parsedEntry.X509Cert.NotAfter) {
			return
		}

		for _, dn := range getDomainNames(parsedEntry) {
			nameChan <- dn
		}

	}, func(entry *ct.RawLogEntry) {
		// nop
	})
	close(nameChan)
	<-done
	if err != nil {
		panic(err)
	}

}

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func getDomainNames(entry *ct.LogEntry) []string {
	nameMap := make(map[string]any)
	for _, name := range entry.X509Cert.DNSNames {
		nameMap[removeWildcard(removeWWW(name))] = nil
	}

	names := make([]string, 0, len(nameMap))
	for name := range nameMap {
		names = append(names, name)
	}
	return names
}

func removeWWW(dn string) string {
	if strings.HasPrefix(dn, "www.") {
		return dn[4:]
	}
	return dn
}

func removeWildcard(dn string) string {
	if strings.HasPrefix(dn, "*.") {
		return dn[2:]
	}
	return dn
}

// Prints out a short bit of info about |precert|, found at |index| in the specified log
func logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		log.Printf("Process precert at index %d: CN: '%s' Issuer: %s", entry.Index, parsedEntry.Precert.TBSCertificate.Subject.CommonName, parsedEntry.Precert.TBSCertificate.Issuer.CommonName)
	}
}

func getFileWriter(path string, zip bool) (io.Writer, func() error, error) {
	outFile, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}

	bufWriter := bufio.NewWriter(outFile)

	if !zip {
		return bufWriter, func() error {
			bufWriter.Flush()
			return outFile.Close()
		}, nil
	}

	zw, err := zstd.NewWriter(bufWriter)
	if err != nil {
		outFile.Close()
		return nil, nil, err
	}

	return zw, func() error {
		zw.Close()
		bufWriter.Flush()
		return outFile.Close()
	}, nil
}
