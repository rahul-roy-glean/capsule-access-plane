package proxy

import (
	"io"
	"net"
	"sync"
)

// tunnel copies bytes bidirectionally between two connections until one side
// closes or an error occurs. Used for non-MITM'd CONNECT tunnels.
func tunnel(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		// Signal the target that the client is done writing.
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		// Signal the client that the target is done writing.
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
