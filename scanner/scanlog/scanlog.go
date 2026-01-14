package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"
)

var (
	out       = flag.String("out", "", "")
	from      = flag.Int64("from", 0, "")
	to        = flag.Int64("to", 0, "")
	url       = flag.String("url", "", "")
	noPrecert = flag.Bool("no_precert", false, "")
)

func main() {
	runtime.GOMAXPROCS(20)
	flag.Parse()

	if out == nil || *out == "" {
		panic("Please provide 'out'")
	}
	if url == nil || *url == "" {
		panic("Please provide 'url'")
	}

	fmt.Println("out: ", *out)
	fmt.Println("url: ", *url)

	out, closeFunc, err := getFileWriter(*out, zstd.SpeedBetterCompression)
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
		validFrom int64
	}

	nameChan := make(chan resultEntry, 1000)
	done := make(chan bool)
	go func() {
		for entry := range nameChan {
			if _, err := out.Write([]byte(fmt.Sprintf("%v,%v,%v,%v,%v\n", entry.index, entry.name, entry.isPrecert, entry.validFrom, entry.validTo))); err != nil {
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

	g := errgroup.Group{}
	g.SetLimit(2000)

	err = s.Scan(ctx, func(entry *ct.RawLogEntry) {
		g.Go(func() error {
			if entry.Index%10000 == 0 {
				log.Printf("At %v", entry.Index)
			}

			parsedEntry, err := entry.ToLogEntry()
			if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
				log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
				return nil
			}

			if now.After(parsedEntry.X509Cert.NotAfter) {
				return nil
			}

			for _, dn := range getDomainNames(parsedEntry) {
				nameChan <- resultEntry{name: dn, index: entry.Index, isPrecert: 0, validFrom: parsedEntry.X509Cert.NotBefore.Unix(), validTo: parsedEntry.X509Cert.NotAfter.Unix()}
			}

			return nil
		})
	}, func(entry *ct.RawLogEntry) {
		g.Go(func() error {
			if entry.Index%10000 == 0 {
				log.Printf("At %v", entry.Index)
			}

			if *noPrecert {
				return nil
			}

			parsedEntry, err := entry.ToLogEntry()

			if x509.IsFatal(err) || parsedEntry.Precert == nil || parsedEntry.Precert.TBSCertificate == nil {
				log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
				return nil
			}

			if now.After(parsedEntry.Precert.TBSCertificate.NotAfter) {
				return nil
			}

			for _, dn := range getDomainNames(parsedEntry) {
				nameChan <- resultEntry{name: dn, index: entry.Index, isPrecert: 1, validFrom: parsedEntry.Precert.TBSCertificate.NotBefore.Unix(), validTo: parsedEntry.Precert.TBSCertificate.NotAfter.Unix()}
			}

			return nil
		})
	})

	log.Println("Took ", time.Since(now))

	g.Wait()
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
			nameMap[name] = nil
		}
	}

	if entry.Precert != nil && entry.Precert.TBSCertificate != nil {
		for _, name := range entry.Precert.TBSCertificate.DNSNames {
			nameMap[name] = nil
		}
	}

	names := make([]string, 0, len(nameMap))
	for name := range nameMap {
		names = append(names, name)
	}
	return names
}

func getFileWriter(path string, level zstd.EncoderLevel) (io.Writer, func() error, error) {
	outFile, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}

	bufWriter := bufio.NewWriter(outFile)

	zw, err := zstd.NewWriter(bufWriter, zstd.WithEncoderLevel(level))
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
