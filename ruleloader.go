package main

import (
	"code.google.com/p/go-charset/charset"
	_ "code.google.com/p/go-charset/data"
	"encoding/xml"
	"log"
	"net/http"
	"sync"
)

type Rules struct {
	Signatures []struct {
		Id     string `xml:"ID"`
		Name   string `xml:"NAME"`
		Time   string `xml:"TIME"`
		Format string `xml:"FORMAT"`
		Sig    string `xml:"SIG"`
	} `xml:"SIGNATURE"`
	m *sync.RWMutex
}

func loadRules(r *Rules) {
	log.Printf("Downloading rules from %s...", ruleUrl)
	resp, err := http.Get(ruleUrl)
	if err != nil {
		log.Fatal(err)
	}

	p := xml.NewDecoder(resp.Body)
	p.CharsetReader = charset.NewReader
	r.m.Lock()
	defer r.m.Unlock()
	if err := p.Decode(&r); err != nil {
		log.Fatal("Error parsing XML rules file: ", err)
	}

	log.Printf("Loaded %d rules in memory", len(r.Signatures))
}
