package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/engine"
	"github.com/kurokagi/kurokagi/internal/openapi"
	"github.com/kurokagi/kurokagi/internal/strictjson"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println("Kurokagi authorization scanner\n\nUsage:\n  kuro scan -config FILE [-out FILE]\n  kuro retest -config FILE -finding FILE [-out FILE]\n  kuro validate -config FILE\n  kuro --version\n\nRetest accepts versioned fingerprint inputs or previous Kurokagi findings. It is targeted and does not run a full scan. Read checks use current discovery; opt-in POST, PUT/PATCH, and disposable DELETE retests use fresh controlled-resource lifecycles and the current mutation policy. Use local controlled fixtures for end-to-end mutation testing.")
		return 0
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Println("kuro " + engine.Version)
		return 0
	}
	if args[0] != "scan" && args[0] != "validate" && args[0] != "retest" {
		fmt.Fprintln(os.Stderr, "unknown command; use kuro --help")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := f.String("config", "", "versioned YAML or JSON configuration")
	out := f.String("out", "", "write scan JSON to this file (default stdout)")
	findingPath := f.String("finding", "", "Kurokagi retest input JSON (one input or array)")
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
	if args[0] == "retest" {
		if *findingPath == "" {
			fmt.Fprintln(os.Stderr, "-finding is required")
			return 2
		}
		inputs, err := loadRetestInputs(*findingPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "retest input error: invalid versioned input")
			return 2
		}
		s, err := engine.New(c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "configuration error:", err)
			return 2
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, deadlineCancel := context.WithTimeout(ctx, 24*time.Hour)
		defer deadlineCancel()
		seen := map[string]bool{}
		results := make([]engine.RetestResult, 0, len(inputs))
		for _, in := range inputs {
			if seen[in.Fingerprint] {
				continue
			}
			seen[in.Fingerprint] = true
			results = append(results, s.Retest(ctx, in))
		}
		b, err := json.MarshalIndent(struct {
			SchemaVersion string                `json:"schema_version"`
			Results       []engine.RetestResult `json:"results"`
		}{"1", results}, "", "  ")
		if err != nil {
			return 3
		}
		if *out != "" {
			if err = os.WriteFile(*out, b, 0600); err != nil {
				fmt.Fprintln(os.Stderr, "retest execution failed: cannot write output")
				return 3
			}
		} else {
			fmt.Println(string(b))
		}
		code := 0
		for _, result := range results {
			switch result.Outcome {
			case "STILL_PRESENT":
				if code < 1 {
					code = 1
				}
			case "INCONCLUSIVE":
				if code < 4 {
					code = 4
				}
			case "NOT_TESTABLE":
				if result.ReasonCode == "INVALID_INPUT" {
					return 2
				}
				if code < 4 {
					code = 4
				}
			}
			if result.ReasonCode == "CANCELLED" {
				return 5
			}
		}
		return code
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
	}
	if len(r.Errors) > 0 {
		return 3
	}
	if r.Status == "findings" {
		return 1
	}
	if r.Completion == "partial" {
		return 4
	}
	return 0
}

func loadRetestInputs(path string) ([]engine.RetestInput, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := strictjson.RejectDuplicateKeys(b); err != nil {
		return nil, fmt.Errorf("invalid retest JSON")
	}
	decode := func(data []byte, dst any) error {
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(dst); err != nil {
			return err
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return fmt.Errorf("trailing data")
		}
		return nil
	}
	parseOne := func(data []byte) (engine.RetestInput, error) {
		var in engine.RetestInput
		if err := decode(data, &in); err == nil && in.SchemaVersion == "1" {
			return in, nil
		}
		// Kurokagi scan findings are accepted as source records. Only the
		// semantic selector and inert fingerprint material are retained.
		var finding engine.Finding
		if err := decode(data, &finding); err != nil {
			return engine.RetestInput{}, err
		}
		if finding.Fingerprint == "" {
			return engine.RetestInput{}, fmt.Errorf("missing source fingerprint")
		}
		return engine.RetestInput{SchemaVersion: "1", Fingerprint: finding.Fingerprint, Classification: finding.Type, Resource: finding.Resource, Victim: finding.VictimIdentity, Actor: finding.AccessingIdentity, Relationship: finding.Relationship, Method: finding.Method, Path: finding.Path, ResourceRef: finding.ResourceRef}, nil
	}
	var many []engine.RetestInput
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var raw []json.RawMessage
		if err := decode(b, &raw); err != nil {
			return nil, err
		}
		for _, item := range raw {
			in, err := parseOne(item)
			if err != nil {
				return nil, err
			}
			many = append(many, in)
		}
	} else {
		in, err := parseOne(b)
		if err != nil {
			return nil, err
		}
		many = []engine.RetestInput{in}
	}
	if len(many) == 0 {
		return nil, fmt.Errorf("empty retest input")
	}
	for _, in := range many {
		if in.SchemaVersion != "1" || len(in.Fingerprint) != 64 {
			return nil, fmt.Errorf("invalid retest input")
		}
		if _, err := hex.DecodeString(in.Fingerprint); err != nil {
			return nil, fmt.Errorf("invalid retest input")
		}
	}
	semanticKey := func(in engine.RetestInput) string {
		return strings.Join([]string{in.Classification, in.Resource, in.Victim, in.Actor, in.Relationship, in.Method, in.Path}, "\x00")
	}
	sort.Slice(many, func(i, j int) bool {
		if many[i].Fingerprint != many[j].Fingerprint {
			return many[i].Fingerprint < many[j].Fingerprint
		}
		if semanticKey(many[i]) != semanticKey(many[j]) {
			return semanticKey(many[i]) < semanticKey(many[j])
		}
		return many[i].ResourceRef < many[j].ResourceRef
	})
	unique := many[:0]
	for _, in := range many {
		if len(unique) > 0 && unique[len(unique)-1].Fingerprint == in.Fingerprint {
			if semanticKey(unique[len(unique)-1]) != semanticKey(in) {
				return nil, fmt.Errorf("conflicting selectors share a finding fingerprint")
			}
			if unique[len(unique)-1].ResourceRef != in.ResourceRef {
				unique[len(unique)-1].ResourceRef = ""
			}
			continue
		}
		unique = append(unique, in)
	}
	return unique, nil
}
