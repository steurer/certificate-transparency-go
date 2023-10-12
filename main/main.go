package main

import (
	"bufio"
	"context"
	"crypto/sha256" //new import
	"encoding/hex"  //new import
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings" //new import
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

//const maxEntriesPerFile = 10000000

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

	// out, closeFunc, err := getFileWriter(*out, zstd.SpeedBetterCompression)
	// if err != nil {
	// 	panic(err)
	// }
	// defer closeFunc()

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
		hash      string //added
		index     int64
		name      string
		isPrecert int
		validFrom int64
		validTo   int64
	}

	// Define a variable to keep track of the number of entries in the current output file
	entriesWritten := 0
	maxEntriesPerFile := 10_000_000 // 10 million entries

	nameChan := make(chan resultEntry, 1000)
	done := make(chan bool)

	// Define a function to create a new output file
	createNewOutputFile := func(fileNum int) (io.Writer, func() error, error) {
		filePath := fmt.Sprintf("%s-%d.csv.zst", *out, fileNum)
		return getFileWriter(filePath, zstd.SpeedBetterCompression)
	}

	out, closeFunc, err := createNewOutputFile(1)
	if err != nil {
		panic(err)
	}
	defer closeFunc()

	go func() {
		fileNum := 1
		for entry := range nameChan {
			if entriesWritten >= maxEntriesPerFile {
				// Close the current file and create a new one
				closeFunc()
				fileNum++
				out, closeFunc, err = createNewOutputFile(fileNum)
				if err != nil {
					panic(err)
				}
				entriesWritten = 0
			}

			if _, err := out.Write([]byte(fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v\n", entry.hash, entry.index, entry.name, entry.isPrecert, entry.validFrom, entry.validTo, entry.validTo))); err != nil {
				panic(err)
			}
			entriesWritten++
		}

		// Close the last file
		closeFunc()
		done <- true
	}()

	// nameChan := make(chan resultEntry, 1000)
	// done := make(chan bool)
	// //modified here to ptint hash id as well
	// go func() {
	// 	for entry := range nameChan {
	// 		if _, err := out.Write([]byte(fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v\n", entry.hash, entry.index, entry.name, entry.isPrecert, entry.validFrom, entry.validTo, entry.validTo))); err != nil {
	// 			panic(err)
	// 		}
	// 	}
	// 	done <- true
	// }()

	// removed previous now and added a new
	now := time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC)

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
			// added logic - from 2017
			if parsedEntry.X509Cert.NotBefore.After(now) {
				hash, names := getDomainNames(parsedEntry)
				nameChan <- resultEntry{
					hash:      hash,
					name:      strings.Join(names, ","), // Join domain names with a comma
					index:     entry.Index,
					isPrecert: 0,
					validFrom: parsedEntry.X509Cert.NotBefore.Unix(),
					validTo:   parsedEntry.X509Cert.NotAfter.Unix(),
				}
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
			// added logic - from 2017
			if parsedEntry.Precert.TBSCertificate.NotBefore.After(now) {
				hash, names := getDomainNames(parsedEntry)
				nameChan <- resultEntry{
					hash:      hash,
					name:      strings.Join(names, ","), // Join domain names with a comma
					index:     entry.Index,
					isPrecert: 1,
					validFrom: parsedEntry.Precert.TBSCertificate.NotBefore.Unix(),
					validTo:   parsedEntry.Precert.TBSCertificate.NotAfter.Unix(),
				}
			}
			// Removed the filtering for unexpired certs

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
// modified to include hashing
func getDomainNames(entry *ct.LogEntry) (hash string, names []string) {
	nameMap := make(map[string]struct{})

	if entry.X509Cert != nil {
		for _, name := range entry.X509Cert.DNSNames {
			nameMap[name] = struct{}{}
		}
	}

	if entry.Precert != nil && entry.Precert.TBSCertificate != nil {
		for _, name := range entry.Precert.TBSCertificate.DNSNames {
			nameMap[name] = struct{}{}
		}
	}

	names = make([]string, 0, len(nameMap))
	for name := range nameMap {
		names = append(names, name)
	}

	// Create a hash over the domain names
	hashBytes := sha256.Sum256([]byte(strings.Join(names, ",")))
	hash = hex.EncodeToString(hashBytes[:])

	return hash, names
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
