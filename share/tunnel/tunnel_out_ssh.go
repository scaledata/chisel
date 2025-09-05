package tunnel

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/sizestr"
	"golang.org/x/crypto/ssh"
)

func (t *Tunnel) handleSSHRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "ping":
			r.Reply(true, []byte("pong"))
		default:
			t.Debugf("Unknown request: %s", r.Type)
		}
	}
}

func (t *Tunnel) handleSSHChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		go t.handleSSHChannel(ch)
	}
}

func (t *Tunnel) handleSSHChannel(ch ssh.NewChannel) {
	if !t.Config.Outbound {
		t.Debugf("Denied outbound connection")
		ch.Reject(ssh.Prohibited, "Denied outbound connection")
		return
	}
	remote := string(ch.ExtraData())
	//extract protocol
	hostPort, proto := settings.L4Proto(remote)
	udp := proto == "udp"
	socks := hostPort == "socks"
	if socks && t.socksServer == nil {
		t.Debugf("Denied socks request, please enable socks")
		ch.Reject(ssh.Prohibited, "SOCKS5 is not enabled")
		return
	}
	sshChan, reqs, err := ch.Accept()
	if err != nil {
		t.Debugf("Failed to accept stream: %s", err)
		return
	}
	stream := io.ReadWriteCloser(sshChan)
	//cnet.MeterRWC(t.Logger.Fork("sshchan"), sshChan)
	defer stream.Close()
	go ssh.DiscardRequests(reqs)
	l := t.Logger.Fork("host#%s: conn#%d", hostPort, t.connStats.New())
	//ready to handle
	t.connStats.Open()
	l.Debugf("Open %s", t.connStats.String())
	if socks {
		err = t.handleSocks(stream)
	} else if udp {
		err = t.handleUDP(l, stream, hostPort)
	} else {
		err = t.handleTCP(l, stream, hostPort)
	}
	t.connStats.Close()
	errmsg := ""
	if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
		errmsg = fmt.Sprintf(" (error %s)", err)
	}
	l.Debugf("Close %s%s", t.connStats.String(), errmsg)
}

func (t *Tunnel) handleSocks(src io.ReadWriteCloser) error {
	return t.socksServer.ServeConn(cnet.NewRWCConn(src))
}

func (t *Tunnel) handleTCP(l *cio.Logger, src io.ReadWriteCloser, hostPort string) error {
	// Check if the host is blocked - hardcoded for specific endpoint
	if strings.Contains(hostPort, "rubrikprodstorageacc.blob.core.windows.net") || strings.Contains(hostPort, "rubrikdevstorageacc.blob.core.windows.net") {
		l.Debugf("Blocked connection to %s", hostPort)
		// Read and discard data to save egress bandwidth while appearing natural to client
		const copyBytesLimit = 64 * 1024 // 64KB limit to prevent resource exhaustion

		_, err := io.CopyN(io.Discard, src, copyBytesLimit)
		if err != nil {
			// Seeing large number of EOF logs so skipping that in errors
			if err != io.EOF {
				l.Debugf("Error in copying data from blocked connection: %v", err)
			}
		}
		src.Close()
		return nil // Return nil to avoid propagating EOF errors
	}

	dst, err := net.Dial("tcp", hostPort)
	if err != nil {
		return err
	}
	s, r := cio.Pipe(src, dst)
	l.Debugf("sent %s received %s", sizestr.ToString(s), sizestr.ToString(r))
	return nil
}
