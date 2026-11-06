//go:build !windows

package main

// The non-Windows build is an explicit simulator for transport/UI tests.
type simulationDriver struct{}

func newDriver() (InputDriver, bool)             { return simulationDriver{}, false }
func (simulationDriver) Move(int32, int32) error { return nil }
func (simulationDriver) Click(string) error      { return nil }
func (simulationDriver) Scroll(int32) error      { return nil }
func (simulationDriver) Key(uint16) error        { return nil }
func (simulationDriver) Text([]uint16) error     { return nil }
func openBrowser(string)                         {}
