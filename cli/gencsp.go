package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mikecb/minimalcsp"
)

func main() {
	exactPaths := flag.Bool("exact-paths", false, "list resources by URL rather than by origin")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gencsp [-exact-paths] <url>")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := minimalcsp.StaticCollector{}.Collect(ctx, flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	policy := minimalcsp.Build(page, minimalcsp.Options{ExactPaths: *exactPaths})
	fmt.Println(policy)
	for _, warning := range policy.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	for _, blocker := range policy.Blockers {
		fmt.Fprintln(os.Stderr, "blocked:", blocker)
	}
}
