package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
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
	out       = flag.String("out", "ct_names.zst", "")
	from      = flag.Int64("from", 0, "")
	to        = flag.Int64("to", 100000, "")
	url       = flag.String("url", "https://ct.googleapis.com/logs/eu1/xenon2024/", "")
	noPrecert = flag.Bool("no_precert", true, "")
)

func main() {
	flag.Parse()
	fmt.Println("out: ", *out)
	fmt.Println("url: ", *url)

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
	opts.NumWorkers = 10
	opts.ParallelFetch = 10
	opts.EndIndex = *to
	opts.StartIndex = *from

	s := scanner.NewScanner(c, opts)

	ctx := context.Background()

	type resultEntry struct {
		index     int64
		name      string
		isPrecert int
		validTo   int64
	}

	nameChan := make(chan resultEntry, 1000)
	done := make(chan bool)
	go func() {
		for entry := range nameChan {
			if _, err := out.Write([]byte(fmt.Sprintf("%v,%v,%v,%v\n", entry.index, entry.name, entry.isPrecert, entry.validTo))); err != nil {
				panic(err)
			}
		}
		done <- true
	}()

	now := time.Now()

	f := scanner.NewFetcher(c, &opts.FetcherOptions)
	sth, err := f.Prepare(ctx)
	if err != nil {
		panic(err)
	}
	log.Printf("Got STH: %v", sth)

	err = s.Scan(ctx, func(entry *ct.RawLogEntry) {
		go func() {
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
				nameChan <- resultEntry{name: dn, index: entry.Index, isPrecert: 0, validTo: parsedEntry.X509Cert.NotAfter.Unix()}
			}
		}()
	}, func(entry *ct.RawLogEntry) {
		if entry.Index%10000 == 0 {
			log.Printf("At %v", entry.Index)
		}

		if *noPrecert {
			return
		}

		parsedEntry, err := entry.ToLogEntry()

		if x509.IsFatal(err) || parsedEntry.Precert == nil || parsedEntry.Precert.TBSCertificate == nil {
			log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
			return
		}

		if now.After(parsedEntry.Precert.TBSCertificate.NotAfter) {
			return
		}

		for _, dn := range getDomainNames(parsedEntry) {
			nameChan <- resultEntry{name: dn, index: entry.Index, isPrecert: 1, validTo: parsedEntry.Precert.TBSCertificate.NotAfter.Unix()}
		}
	})

	log.Println("Took %v", time.Since(now))

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

	if entry.X509Cert != nil {
		for _, name := range entry.X509Cert.DNSNames {
			nameMap[removeWildcard(name)] = nil
		}
	}

	if entry.Precert != nil && entry.Precert.TBSCertificate != nil {
		for _, name := range entry.Precert.TBSCertificate.DNSNames {
			nameMap[removeWildcard(name)] = nil
		}
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
