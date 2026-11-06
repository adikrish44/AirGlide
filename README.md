# AirGlide 1.3 — Windows motion remote

Use your iPhone or Android phone as a motion pointer for a Windows PC. The **original Go Windows companion** is the supported implementation in this repository. The unrelated Python prototype has been removed.

## Quick start

1. Download and extract the GitHub ZIP on Windows.
2. Open `START-HERE.html` for instructions.
3. Run `START.cmd` and follow the local setup and pairing instructions.
4. Connect your phone to the same trusted home network.

## Brand and feedback

The canonical English AirGlide logo is `airglide-logo.svg` (also embedded as `source/web/icon.svg`). The setup page and mobile web interface use this SVG. Send Feedback: [@adi__krish](https://www.instagram.com/adi__krish/).

## Important build note

`AirGlide.exe` is an **older prebuilt binary** and does not yet contain the latest logo, UI, and feedback changes. To rebuild on Windows with Go 1.24+:

```powershell
cd source
go test ./...
go build -buildvcs=false -trimpath -ldflags="-s -w" -o ..\AirGlide.exe .
```

The web assets are embedded in the Go binary. Rebuilding is required for updated mobile UI branding. The prebuilt PNG home-screen icons also still need regeneration from the new SVG before branding can be considered complete.

## Security

Use only on a trusted private network. Do not expose the companion to the public internet. Install only certificates created by your own Windows companion.

## Creator

Aditya Krishna Thota · [@adi__krish](https://www.instagram.com/adi__krish/) · [Send Feedback](https://www.instagram.com/adi__krish/)
