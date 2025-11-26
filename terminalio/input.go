package terminalio

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Input(text string) (string, error) {
	var inp string
	fmt.Print(text)
	reader := bufio.NewReader(os.Stdin)
	inp, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	inp = strings.TrimSuffix(inp, "\n")
	inp = strings.TrimSuffix(inp, "\r")
	return inp, nil
}