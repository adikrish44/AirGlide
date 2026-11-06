package main

import (
	"errors"
	"math"
	"unicode/utf16"
)

type Command struct {
	Type   string  `json:"type"`
	DX     float64 `json:"dx,omitempty"`
	DY     float64 `json:"dy,omitempty"`
	Amount float64 `json:"amount,omitempty"`
	Button string  `json:"button,omitempty"`
	Key    string  `json:"key,omitempty"`
	Text   string  `json:"text,omitempty"`
	ID     int64   `json:"id,omitempty"`
}

type InputDriver interface {
	Move(int32, int32) error
	Click(string) error
	Scroll(int32) error
	Key(uint16) error
	Text([]uint16) error
}

var keyCodes = map[string]uint16{
	"enter": 0x0D, "escape": 0x1B, "backspace": 0x08, "tab": 0x09,
	"left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
	"volume_up": 0xAF, "volume_down": 0xAE, "mute": 0xAD,
	"play_pause": 0xB3, "next": 0xB0, "previous": 0xB1,
}

func validNumber(v float64) bool     { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func bounded(v, limit float64) int32 { return int32(math.Round(math.Max(-limit, math.Min(limit, v)))) }

func dispatch(d InputDriver, c Command) error {
	switch c.Type {
	case "move":
		if !validNumber(c.DX) || !validNumber(c.DY) {
			return errors.New("invalid movement")
		}
		return d.Move(bounded(c.DX, 500), bounded(c.DY, 500))
	case "click":
		if c.Button != "left" && c.Button != "right" {
			return errors.New("invalid button")
		}
		return d.Click(c.Button)
	case "scroll":
		if !validNumber(c.Amount) {
			return errors.New("invalid scroll")
		}
		return d.Scroll(bounded(c.Amount, 1200))
	case "key":
		key, ok := keyCodes[c.Key]
		if !ok {
			return errors.New("unsupported key")
		}
		return d.Key(key)
	case "text":
		if len(c.Text) > 1024 || len([]rune(c.Text)) > 256 {
			return errors.New("text is too long")
		}
		return d.Text(utf16.Encode([]rune(c.Text)))
	default:
		return errors.New("unsupported command")
	}
}
