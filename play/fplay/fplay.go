package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
)

var (
	inDir      = flag.String("id", "", "Input directory where CSV files are located")
	outDir     = flag.String("od", "", "Output directory for processed files")
	maxEntries = 10000000 // Maximum number of entries per output file
)

func main() {
	flag.Parse()

	if *inDir == "" {
		log.Fatal("Please provide 'id' (Input directory)")
	}
	if *outDir == "" {
		log.Fatal("Please provide 'od' (Output directory)")
	}

	fmt.Println("Input Directory:", *inDir)
	fmt.Println("Output Directory:", *outDir)

	dnsNameMap := make(map[string]struct {
		FirstSeen string
		LastSeen  string
	})

	err := processCSVFiles(*inDir, dnsNameMap)
	if err != nil {
		log.Fatal("Error processing CSV files:", err)
	}

	// Sort the keys (DNS names) for a consistent output order
	var dnsNames []string
	for dnsName := range dnsNameMap {
		dnsNames = append(dnsNames, dnsName)
	}
	sort.Strings(dnsNames)

	// Create the output directory if it doesn't exist
	if _, err := os.Stat(*outDir); os.IsNotExist(err) {
		err := os.MkdirAll(*outDir, 0755)
		if err != nil {
			log.Fatal("Error creating output directory:", err)
		}
	}

	// Create the first output file
	outFile, err := createOutputFile(*outDir, 0)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	defer outFile.Close()

	writer := csv.NewWriter(outFile)

	// Process and save each DNS name separately
	entriesCount := 0
	for _, dnsName := range dnsNames {
		entry := dnsNameMap[dnsName]
		record := []string{dnsName, entry.FirstSeen, entry.LastSeen}

		err := writer.Write(record)
		if err != nil {
			log.Fatal("Error writing to output file:", err)
		}

		entriesCount++

		if entriesCount >= maxEntries {
			writer.Flush()
			outFile.Close()

			outFile, err = createOutputFile(*outDir, entriesCount/maxEntries)
			if err != nil {
				log.Fatal("Error creating output file:", err)
			}

			writer = csv.NewWriter(outFile)
			entriesCount = 0
		}
	}
	writer.Flush()
}

func processCSVFiles(inputDir string, dnsNameMap map[string]struct {
	FirstSeen string
	LastSeen  string
}) error {
	files, err := filepath.Glob(filepath.Join(inputDir, "bucket_*.csv"))
	if err != nil {
		return err
	}

	for _, file := range files {
		if err := processCSVFile(file, dnsNameMap); err != nil {
			return err
		}
	}

	return nil
}

func processCSVFile(filename string, dnsNameMap map[string]struct {
	FirstSeen string
	LastSeen  string
}) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		if len(record) < 2 {
			continue
		}

		dnsName := record[0]
		timestamp := record[1]

		entry, exists := dnsNameMap[dnsName]

		if !exists || timestamp < entry.FirstSeen {
			entry.FirstSeen = timestamp
		}

		if !exists || timestamp > entry.LastSeen {
			entry.LastSeen = timestamp
		}

		dnsNameMap[dnsName] = entry
	}

	return nil
}

func createOutputFile(outDir string, fileNumber int) (*os.File, error) {
	filename := fmt.Sprintf("output_%d.csv", fileNumber)
	outFilePath := filepath.Join(outDir, filename)
	outFile, err := os.Create(outFilePath)
	if err != nil {
		return nil, err
	}
	return outFile, nil
}
