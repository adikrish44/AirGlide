//go:build windows && (amd64 || arm64)

package main

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

// Win32 INPUT is 40 bytes on Windows x64/ARM64. The largest union member,
// MOUSEINPUT, begins at byte 8. No pointers are retained after SendInput.
type winInput struct {
	Kind uint32
	Pad  uint32
	Data [32]byte
}
type winDriver struct{ send *syscall.LazyProc }

func newDriver() (InputDriver, bool) {
	return &winDriver{syscall.NewLazyDLL("user32.dll").NewProc("SendInput")}, true
}
func (d *winDriver) inject(items []winInput) error {
	if len(items) == 0 {
		return nil
	}
	n, _, _ := d.send.Call(uintptr(len(items)), uintptr(unsafe.Pointer(&items[0])), unsafe.Sizeof(items[0]))
	if n != uintptr(len(items)) {
		return fmt.Errorf("Windows blocked input. Return to a normal desktop window; administrator prompts and the lock screen cannot be controlled")
	}
	return nil
}
func mouseInput(dx, dy int32, data, flags uint32) winInput {
	i := winInput{}
	binary.LittleEndian.PutUint32(i.Data[0:4], uint32(dx))
	binary.LittleEndian.PutUint32(i.Data[4:8], uint32(dy))
	binary.LittleEndian.PutUint32(i.Data[8:12], data)
	binary.LittleEndian.PutUint32(i.Data[12:16], flags)
	return i
}
func keyboardInput(key, scan uint16, flags uint32) winInput {
	i := winInput{Kind: 1}
	binary.LittleEndian.PutUint16(i.Data[0:2], key)
	binary.LittleEndian.PutUint16(i.Data[2:4], scan)
	binary.LittleEndian.PutUint32(i.Data[4:8], flags)
	return i
}
func (d *winDriver) Move(x, y int32) error { return d.inject([]winInput{mouseInput(x, y, 0, 1)}) }
func (d *winDriver) Click(button string) error {
	down, up := uint32(2), uint32(4)
	if button == "right" {
		down, up = 8, 16
	}
	return d.inject([]winInput{mouseInput(0, 0, 0, down), mouseInput(0, 0, 0, up)})
}
func (d *winDriver) Scroll(v int32) error {
	return d.inject([]winInput{mouseInput(0, 0, uint32(v), 0x800)})
}
func (d *winDriver) Key(key uint16) error {
	flags := uint32(0)
	if key >= 0x21 && key <= 0x28 {
		flags = 1
	}
	return d.inject([]winInput{keyboardInput(key, 0, flags), keyboardInput(key, 0, flags|2)})
}
func (d *winDriver) Text(units []uint16) error {
	i := make([]winInput, 0, len(units)*2)
	for _, u := range units {
		i = append(i, keyboardInput(0, u, 4), keyboardInput(0, u, 6))
	}
	return d.inject(i)
}
func openBrowser(url string) {
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}
