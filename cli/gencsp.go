package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/mikecb/minimalcsp"
)

func main() {
	target := os.Args[1]
	resp, err := http.Get(target)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	minimalcsp.MakePolicy(string(body))
}
