package main

import (
	"fmt"
	"log"
	"os"

	"github.com/niktheblak/cryptcli/pkg/scrypt"
)

func main() {
	var password string
	if len(os.Args) == 1 {
		if _, err := fmt.Fscan(os.Stdin, &password); err != nil {
			log.Fatal(err)
		}
	} else {
		password = os.Args[1]
	}
	hash, err := scrypt.GenerateFromPassword([]byte(password))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hash)
}
