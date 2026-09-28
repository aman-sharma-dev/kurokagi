package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/engine"
	"github.com/kurokagi/kurokagi/internal/openapi"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println("Kurokagi authorization scanner\n\nUsage:\n  kuro scan -config FILE [-out FILE]\n  kuro validate -config FILE\n  kuro --version\n\nOnly configured GET authorization checks are active in v0.1.")
		return 0
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Println("kuro " + engine.Version)
		return 0
	}
	if args[0] != "scan" && args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "unknown command; use kuro --help")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := f.String("config", "", "versioned YAML or JSON configuration")
	out := f.String("out", "", "write scan JSON to this file (default stdout)")
	if f.Parse(args[1:]) != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		return 2
	}
	c, e := config.Load(*cfgPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", e)
		return 2
	}
	d, e := openapi.Load(c.OpenAPI.Path)
	if e != nil {
		fmt.Fprintln(os.Stderr, "configuration error: OpenAPI:", e)
		return 2
	}
	_ = d
	if args[0] == "validate" {
		fmt.Println("configuration and OpenAPI document are valid")
		return 0
	}
	s, e := engine.New(c)
	if e != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", e)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadlineCancel := context.WithTimeout(ctx, 24*time.Hour)
	defer deadlineCancel()
	r, e := s.Scan(ctx)
	if e != nil {
		fmt.Fprintln(os.Stderr, "scan execution failed:", e)
		return 3
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		fmt.Fprintln(os.Stderr, "scan execution failed")
		return 3
	}
	if *out != "" {
		if e = os.WriteFile(*out, b, 0600); e != nil {
			fmt.Fprintln(os.Stderr, "scan execution failed: cannot write output")
			return 3
		}
	} else {
		fmt.Println(string(b))
	}
	switch r.Status {
	case "cancelled":
		return 5
	case "findings":
		return 1
	default:
		if len(r.Errors) > 0 {
			return 3
		}
		return 0
	}
}
