package main

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var (
	inDir  = flag.String("id", "", "Input directory where compressed files are located")
	outDir = flag.String("od", "", "Output directory for processed files")
)

func main() {
	flag.Parse()

	if inDir == nil || *inDir == "" {
		log.Fatal("Please provide 'id' (Input directory)")
	}
	if outDir == nil || *outDir == "" {
		log.Fatal("Please provide 'of' (Output directory)")
	}

	fmt.Println("Input Directory: ", *inDir)
	fmt.Println("Output Directory: ", *outDir)

	bucketFiles := make(map[int]*os.File)

	getOrCreateBucketFile := func(bucketNum int) (*os.File, error) {
		if file, ok := bucketFiles[bucketNum]; ok {
			return file, nil
		}

		outDirPath := filepath.Join(*outDir, fmt.Sprintf("bucket_%d.csv", bucketNum))
		file, err := os.OpenFile(outDirPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return nil, err
		}
		bucketFiles[bucketNum] = file
		return file, nil
	}

	// Define a function to process a single file
	processFile := func(filePath string) {
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("Error opening file %s: %v", filePath, err)
			return
		}
		defer file.Close()

		reader, err := zstd.NewReader(file)
		if err != nil {
			log.Printf("Error creating Zstd reader for file %s: %v", filePath, err)
			return
		}
		defer reader.Close()

		scanner := bufio.NewScanner(reader)

		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ",")
			if len(parts) != 7 {
				logError(fmt.Sprintf("Skipping invalid entry in file %s: %v\n", filePath, line), *outDir)
				continue
			}

			names := strings.Split(parts[2], ";")
			leafTime := parts[6]

			for _, name := range names {
				n := hashBucket(name)
				entry := fmt.Sprintf("%s, %s", name, leafTime)

				// Write the entry to the matching bucket file
				bucketFile, err := getOrCreateBucketFile(n)
				if err != nil {
					log.Printf("Error creating or opening bucket file: %v", err)
					continue
				}

				_, writeErr := bucketFile.WriteString(entry + "\n")
				if writeErr != nil {
					log.Printf("Error writing to bucket file: %v", writeErr)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Error scanning file %s: %v", filePath, err)
		}
	}

	err := filepath.Walk(*inDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error scanning directory: %v", err)
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".zst") {
			processFile(path)
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error scanning directory: %v", err)
	}

	// Close all the bucket files
	for _, file := range bucketFiles {
		file.Close()
	}
}

func hashBucket(name string) int {
	hashBytes := md5.Sum([]byte(name))
	hash := int(binary.LittleEndian.Uint64(hashBytes[:8]))
	return int(math.Abs(float64(hash % 128)))
}

func logError(errMsg string, outDir string) {
	errorLogFilePath := filepath.Join(outDir, "error_log.txt")
	logFile, err := os.OpenFile(errorLogFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Printf("Error opening error log file: %v", err)
		return
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)
	logger.Println(errMsg)
}
