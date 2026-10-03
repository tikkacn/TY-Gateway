// rule-seed exports only the public portion of validated server rule packages.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"tygateway/internal/model"
	"tygateway/internal/rules"
	"tygateway/internal/ruleseed"
)

func main() {
	input := flag.String("input-dir", "", "validated public cloud rule package directory")
	output := flag.String("output-dir", "", "generated public seed directory")
	flag.Parse()
	if *input == "" || *output == "" {
		panic("input-dir and output-dir required")
	}
	for _, profile := range ruleseed.Profiles {
		file, err := os.Open(filepath.Join(*input, profile+".json"))
		must(err)
		raw, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
		_ = file.Close()
		must(err)
		if len(raw) > 8<<20 {
			panic("rule package too large")
		}
		var source struct {
			Profile     string       `json:"profile"`
			Name        string       `json:"name"`
			Version     string       `json:"version"`
			PublishedAt string       `json:"published_at"`
			Categories  []string     `json:"categories"`
			Rules       []model.Rule `json:"rules"`
		}
		must(json.Unmarshal(raw, &source))
		if source.Profile != profile {
			panic("wrong seed profile")
		}
		for _, r := range source.Rules {
			if r.DeviceID != "" || r.SourceIP != "" || r.SourceMAC != "" || !r.Enabled {
				panic("rule seed contains device-specific or disabled rules")
			}
		}
		p := ruleseed.Package{Profile: source.Profile, Name: source.Name, Version: source.Version, PublishedAt: source.PublishedAt, Categories: source.Categories, Rules: rules.New().CompilePolicy(source.Rules)}
		must(ruleseed.Validate(p))
		data, err := json.Marshal(p)
		must(err)
		must(os.MkdirAll(*output, 0755))
		path := filepath.Join(*output, profile+".json.gz")
		f, err := os.Create(path + ".tmp")
		must(err)
		z, err := gzip.NewWriterLevel(f, gzip.BestCompression)
		must(err)
		_, err = z.Write(data)
		must(err)
		must(z.Close())
		must(f.Close())
		must(os.Rename(path+".tmp", path))
		fmt.Printf("%s version=%s rules=%d public-only seed generated\n", profile, p.Version[:12], len(p.Rules))
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
