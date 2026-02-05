//go:build windows

package main

import (
	"log/slog"
	"syscall"

	"github.com/brahma-adshonor/gohook"
)

//go:noinline
func wsaioctlHook(s syscall.Handle, iocc uint32, inbuf *byte, cbif uint32, outbuf *byte, cbob uint32, cbbr *uint32, overlapped *syscall.Overlapped, completionRoutine uintptr) error {
	// TODO: Upstream a fix to Wine
	if iocc == syscall.IOC_IN|syscall.IOC_VENDOR|15 { // SIO_UDP_NETRESET
		return nil
	}

	return wsaioctlTrampoline(s, iocc, inbuf, cbif, outbuf, cbob, cbbr, overlapped, completionRoutine)
}

func wsaioctlTrampoline(s syscall.Handle, iocc uint32, inbuf *byte, cbif uint32, outbuf *byte, cbob uint32, cbbr *uint32, overlapped *syscall.Overlapped, completionRoutine uintptr) error {
	return nil
}

func initPlatSpecific() {
	if err := gohook.Hook(syscall.WSAIoctl, wsaioctlHook, wsaioctlTrampoline); err != nil {
		slog.Error("Failed to hook syscall.WSAIoctl", "err", err)
	}
}
