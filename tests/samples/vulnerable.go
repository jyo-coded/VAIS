package main

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"
)

func vulnerable_function_1(userInput string) {
	// Rule 1: exec.Command with user input (Command Injection)
	cmd := exec.Command("bash", "-c", userInput)
	cmd.Run()
}

func vulnerable_function_2() {
	// Rule 2: unsafe.Pointer Usage
	var x int = 10
	ptr := unsafe.Pointer(&x)
	_ = ptr
}

func vulnerable_function_3() {
	// Rule 3: Ignored Error Returns
	f, _ := os.Open("secret.txt")
	defer f.Close()
	
	_, err := os.Create("test.txt")
}

func vulnerable_function_4(userFormat string) {
	// Rule 4: fmt.Sprintf Format String
	res := fmt.Sprintf(userFormat)
	fmt.Printf(userFormat)
}

func vulnerable_function_5() {
	// Rule 5: os.Args Without Validation
	arg := os.Args[1]
	fmt.Println(arg)
}

func vulnerable_function_6() {
	// Rule 6: Hardcoded Secrets
	apiKey := "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	password := "superSecret123!"
	secretKey = "1234567890abcdef1234567890abcdef"
}

func main() {
	vulnerable_function_5()
	vulnerable_function_1(os.Args[1])
	vulnerable_function_2()
	vulnerable_function_3()
	vulnerable_function_4(os.Args[1])
	vulnerable_function_6()
}