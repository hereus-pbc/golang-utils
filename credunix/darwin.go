//go:build darwin
package main

import (
	"net"
	"syscall"
	"unsafe"
)

func getPeerInfo(c *net.UnixConn) (*PeerInfo, error) {
	raw, err := c.File()
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	var cred syscall.Xucred
	size := uint32(unsafe.Sizeof(cred))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, raw.Fd(), 
		syscall.SOL_LOCAL, syscall.LOCAL_PEERCRED, 
		uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)

	if errno != 0 {
		return nil, errno
	}
	return &PeerInfo{
		Uid: uint32(cred.Uid),
		Gid: uint32(cred.Gid[0]),
		Pid: 0,
	}, nil
}