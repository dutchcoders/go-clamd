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
	"errors"
	"fmt"
	"io"
	"strings"
)

type Clamd struct {
	address string
}

type Stats struct {
	Pools    string
	State    string
	Threads  string
	Memstats string
	Queue    string
}

var EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

func (c *Clamd) newConnection() (*CLAMDConn, error) {
	conn, err := newCLAMDUnixConn(c.address)
	return conn, err
}

func (c *Clamd) simpleCommand(command string) (chan string, error) {
	conn, err := newCLAMDUnixConn(c.address)
	if err != nil {
		return nil, err
	}

	// defer conn.Close()

	err = conn.sendCommand(command)
	if err != nil {
		return nil, err
	}

	ch, wg, err := conn.readResponse()

	go func() {
		// wait for waitgroup
		wg.Wait()

		// close connection
		conn.Close()
	}()

	return ch, err
}

/*
Check the daemon's state (should reply with PONG).
*/
func (c *Clamd) Ping() error {
	ch, err := c.simpleCommand("PING")
	if err != nil {
		return err
	}

	select {
	case s := (<-ch):
		switch s {
		case "PONG":
			return nil
		default:
			return errors.New(fmt.Sprintf("Invalid response, got %s.", s))
		}
	}

	return nil
}

/*
Print program and database versions.
*/
func (c *Clamd) Version() (chan string, error) {
	dataArrays, err := c.simpleCommand("VERSION")
	return dataArrays, err
}

/*
On this command clamd provides statistics about the scan queue, contents of scan
queue, and memory usage. The exact reply format is subject to changes in future
releases.
*/
func (c *Clamd) Stats() (*Stats, error) {
	ch, err := c.simpleCommand("STATS")
	if err != nil {
		return nil, err
	}

	stats := &Stats{}

	for s := range ch {
		if strings.HasPrefix(s, "POOLS") {
			stats.Pools = strings.Trim(s[6:], " ")
		} else if strings.HasPrefix(s, "STATE") {
			stats.State = s
		} else if strings.HasPrefix(s, "THREADS") {
			stats.Threads = s
		} else if strings.HasPrefix(s, "QUEUE") {
			stats.Queue = s
		} else if strings.HasPrefix(s, "MEMSTATS") {
			stats.Memstats = s
		} else if strings.HasPrefix(s, "END") {
		} else {
			//	return nil, errors.New(fmt.Sprintf("Unknown response, got %s.", s))
		}
	}

	return stats, nil
}

/*
Reload the databases.
*/
func (c *Clamd) Reload() error {
	ch, err := c.simpleCommand("RELOAD")
	if err != nil {
		return err
	}

	select {
	case s := (<-ch):
		switch s {
		case "RELOADING":
			return nil
		default:
			return errors.New(fmt.Sprintf("Invalid response, got %s.", s))
		}
	}

	return nil
}

func (c *Clamd) Shutdown() error {
	_, err := c.simpleCommand("SHUTDOWN")
	if err != nil {
		return err
	}

	return err
}

/*
Scan file or directory (recursively) with archive support enabled (a full path is
required).
*/
func (c *Clamd) ScanFile(path string) (chan string, error) {
	command := fmt.Sprintf("SCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive and special file support disabled
(a full path is required).
*/
func (c *Clamd) RawScanFile(path string) (chan string, error) {
	command := fmt.Sprintf("RAWSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file in a standard way or scan directory (recursively) using multiple threads
(to make the scanning faster on SMP machines).
*/
func (c *Clamd) MultiScanFile(path string) (chan string, error) {
	command := fmt.Sprintf("MULTISCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive support enabled and don’t stop
the scanning when a virus is found.
*/
func (c *Clamd) ContScanFile(path string) (chan string, error) {
	command := fmt.Sprintf("CONTSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive support enabled and don’t stop
the scanning when a virus is found.
*/
func (c *Clamd) AllMatchScanFile(path string) (chan string, error) {
	command := fmt.Sprintf("ALLMATCHSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan a stream of data. The stream is sent to clamd in chunks, after INSTREAM,
on the same socket on which the command was sent. This avoids the overhead
of establishing new TCP connections and problems with NAT. The format of the
chunk is: <length><data> where <length> is the size of the following data in
bytes expressed as a 4 byte unsigned integer in network byte order and <data> is
the actual chunk. Streaming is terminated by sending a zero-length chunk. Note:
do not exceed StreamMaxLength as defined in clamd.conf, otherwise clamd will
reply with INSTREAM size limit exceeded and close the connection
*/
func (c *Clamd) ScanStream(r io.Reader) (chan string, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	conn.sendCommand("INSTREAM")

	for {
		buf := make([]byte, CHUNK_SIZE)

		nr, err := r.Read(buf)
		if err != nil {
			break
		}

		if nr == 0 {
			break
		}

		conn.sendChunk(buf[:nr])
	}

	err = conn.sendEOF()
	if err != nil {
		return nil, err
	}

	ch, wg, err := conn.readResponse()

	go func() {
		wg.Wait()
		conn.Close()
	}()

	return ch, nil
}

func NewClamd(address string) *Clamd {
	clamd := &Clamd{address: address}
	return clamd
}
