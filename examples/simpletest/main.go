package main

import (
	"fmt"
	"os"
)

func main() {
	// Check if we're running in daemon mode
	for _, arg := range os.Args {
		if arg == "--daemon" {
			// Start a simple server that listens on stdin and writes to stdout
			fmt.Println("Module server started")
			
			// Read commands from stdin
			for {
				var cmd string
				_, err := fmt.Scanln(&cmd)
				if err != nil {
					break
				}
				
				switch cmd {
				case "info":
					fmt.Println("name: simpletest")
					fmt.Println("description: A simple test module")
					fmt.Println("options: message:string:false:Hello")
				case "execute":
					// Read config
					config := make(map[string]string)
					var key, value string
					for {
						_, err := fmt.Scanln(&key, &value)
						if err != nil || key == "end" {
							break
						}
						config[key] = value
					}
					
					// Execute
					message := config["message"]
					if message == "" {
						message = "Hello"
					}
					fmt.Printf("result: %s\n", message)
					fmt.Println("error:")
				}
			}
			return
		}
	}
	
	// Not running in daemon mode, just exit
	fmt.Println("Simple test module")
}
