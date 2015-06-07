package main

import (
  "fmt"
  "crypto/sha256"
)

func main() {
  M := []byte("This is a great message!")
  H := sha256.Sum256(M)
  fmt.Printf("% x\n", H[:16])
}
