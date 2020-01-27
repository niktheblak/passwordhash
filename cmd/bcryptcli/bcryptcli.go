package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
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
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(hash))
}
