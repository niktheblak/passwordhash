package main

import (
	"log"

	"github.com/niktheblak/passwordhash/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
