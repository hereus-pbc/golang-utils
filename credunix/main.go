package credunix

import "net"

type PeerInfo struct {
	Uid uint32
	Gid uint32
	Pid int32
}

func GetPeerInfo(c *net.UnixConn) (*PeerInfo, error) {
	return getPeerInfo(c)
}
