package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scanner_sinatra_params"
)

func main() {
	dir := "/"
	//subDirToSkip := "skip" // dir/to/walk/skip
	violations := 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", dir, err)
			return err
		}
		/*if info.IsDir() && info.Name() == subDirToSkip {
			fmt.Printf("skipping a dir without errors: %+v \n", info.Name())
			return filepath.SkipDir
		}*/

		if strings.HasSuffix(path, ".rb") {
			//		fmt.Printf("Scanning file: %q\n", path)
			violations += scanFile(path)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("error walking the path %q: %v\n", dir, err)
	}

	//scanFile("code.rb") // to test just one file
	//os.Exit(violations)
	fmt.Println("[CODE SCANNER] Missing Validations:", violations)

}

func scanFile(file string) int {

	fileHandle, err := os.Open(file)
	defer fileHandle.Close()

	if err != nil {
		return -1
	}

	reader := bufio.NewReader(fileHandle)

	var line string

	sinatra := sinatraParamScanner.New(file)
	for {
		line, err = reader.ReadString('\n')

		sinatra.ScanLine(line)

		if err != nil {
			break
		}
	}

	violations := sinatra.GetViolations()
	//fmt.Println("Missing Validations:", violations)
	return violations
}
