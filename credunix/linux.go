//go:build linux
package main

import (
	"net"
	"syscall"
)

func getPeerInfo(c *net.UnixConn) (*PeerInfo, error) {
	raw, err := c.File()
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	ucred, err := syscall.GetsockoptUcred(int(raw.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return nil, err
	}
	return &PeerInfo{
		Uid: ucred.Uid,
		Gid: ucred.Gid,
		Pid: ucred.Pid,
	}, nil
}