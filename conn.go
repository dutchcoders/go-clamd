/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package clamd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

const CHUNK_SIZE = 1024

type CLAMDConn struct {
	net.Conn
}

func (conn *CLAMDConn) sendCommand(command string) error {
	commandBytes := []byte(fmt.Sprintf("n%s\n", command))

	_, err := conn.Write(commandBytes)
	return err
}

func (conn *CLAMDConn) sendEOF() error {
	_, err := conn.Write([]byte{0, 0, 0, 0})
	return err
}

func (conn *CLAMDConn) sendChunk(data []byte) error {
	var buf [4]byte
	lenData := len(data)
	buf[0] = byte(lenData >> 24)
	buf[1] = byte(lenData >> 16)
	buf[2] = byte(lenData >> 8)
	buf[3] = byte(lenData >> 0)

	a := buf

	b := make([]byte, len(a))
	for i := range a {
		b[i] = a[i]
	}

	conn.Write(b)

	_, err := conn.Write(data)
	return err
}

func (c *CLAMDConn) readResponse() (chan string, *sync.WaitGroup, error) {
	var wg sync.WaitGroup

	wg.Add(1)

	// read data
	reader := bufio.NewReader(c)

	// reading
	ch := make(chan string)

	// var dataArrays []string
	go func() {
		defer func() {
			close(ch)
			wg.Done()
		}()

		for {
			line, err := reader.ReadString('\n')
			if err == io.EOF {
				return
			}

			if err != nil {
				return
			}

			line = strings.TrimRight(line, " \t\r\n")

			ch <- line
		}
	}()

	return ch, &wg, nil
}

func newCLAMDTcpConn(address string) (*CLAMDConn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	return &CLAMDConn{Conn: conn}, err
}

func newCLAMDUnixConn(address string) (*CLAMDConn, error) {
	conn, err := net.Dial("unix", address)
	if err != nil {
		return nil, err
	}

	return &CLAMDConn{Conn: conn}, err
}
