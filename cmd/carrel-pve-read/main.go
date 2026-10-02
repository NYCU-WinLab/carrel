package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/pveread"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "inventory" && os.Args[1] != "topology") {
		fmt.Fprintln(os.Stderr, "expected inventory or topology")
		os.Exit(2)
	}
	content, err := os.ReadFile("/etc/carrel/pve-read.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "PVE reader configuration unavailable")
		os.Exit(1)
	}
	var cfg pveread.Config
	if json.Unmarshal(content, &cfg) != nil {
		fmt.Fprintln(os.Stderr, "invalid PVE reader configuration")
		os.Exit(1)
	}
	reader, err := pveread.New(cfg)
	if err == nil {
		defer reader.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var result map[string]any
		result, err = reader.Read(ctx, os.Args[1])
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(result)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
