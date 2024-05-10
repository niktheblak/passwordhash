# passwordhash
CLI for creating salted password hashes with bcrypt, scrypt and argon2.

## Usage

Print a base64 encoded bcrypt hash of a given binary file
```shell
go run main.go bcrypt -e < data.bin
```

Print a base64 encoded argon2 hash of a given password string
```shell
go run main.go argon2 -e "myS3cr3tP4ssW0rd"
```

Print a base64 encoded argon2 hash of a given password string with a custom salt (in hexadecimal format)
```shell
go run main.go argon2 -e -s fa09cf432d5ae1 "myS3cr3tP4ssW0rd"
```

Write a binary argon2 hash of a given password string
```shell
go run main.go argon2 "myS3cr3tP4ssW0rd" > hash.bin
```

Write a binary argon2 hash of a given password string
```shell
go run main.go argon2 < data.bin > hash.bin
```
