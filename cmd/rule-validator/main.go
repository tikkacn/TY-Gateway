package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"tygateway/internal/model"
	"tygateway/internal/rules"
)

func main() {
	var p struct {
		Profile string       `json:"profile"`
		Rules   []model.Rule `json:"rules"`
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, (8<<20)+1))
	if err != nil || len(data) > 8<<20 || json.Unmarshal(data, &p) != nil || len(p.Rules) == 0 {
		fmt.Fprintln(os.Stderr, "invalid package")
		os.Exit(1)
	}
	rendered, err := rules.RenderDaeManaged(model.DaePolicy{Profile: p.Profile, Rules: rules.New().CompilePolicy(p.Rules), Interface: "eth0", ProxyEnabled: true, SubscriptionPresent: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "--render" {
		fmt.Print(string(rendered))
	}
}
