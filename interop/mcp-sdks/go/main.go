// Command harness decodes and re-encodes each JSON-RPC line with the Go SDK's
// exported wire codec, jsonrpc.DecodeMessage and jsonrpc.EncodeMessage.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		msg, err := jsonrpc.DecodeMessage(in.Bytes())
		if err != nil {
			fmt.Fprintf(out, "ERR %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
			continue
		}
		wire, err := jsonrpc.EncodeMessage(msg)
		if err != nil {
			fmt.Fprintf(out, "ERR encode: %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
			continue
		}
		fmt.Fprintf(out, "OK %s\n", base64.StdEncoding.EncodeToString(wire))
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
