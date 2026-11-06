# AirGlide

AirGlide is a mobile-friendly browser remote for controlling a Windows PC from an iPhone or Android phone on the same trusted Wi-Fi network.

## Version 1.0 — working prototype

The user confirmed the remote works. This repository contains the Python Windows companion and mobile web interface. It does not contain a native IPA or APK.

## Quick start

1. Install Python 3.11 or newer on Windows.
2. Run `pip install -r requirements.txt`.
3. Run `python server.py`.
4. Open the local address printed in the terminal on your phone.
5. Enter the six-digit pairing code shown on Windows.

## Controls

Touchpad, left and right clicks, scrolling, text input, and keyboard keys.

## Branding

The minimal logo is defined in [web/logo.json](web/logo.json) and displayed by the mobile web interface. The feedback link opens Instagram.

## Security

Use only on a trusted private local network. Do not expose port 8765 to the public internet. This prototype uses HTTP and WebSocket, not encrypted HTTPS.

## Credits

Created by Aditya Krishna Thota.

[Send Feedback — @adi__krish](https://www.instagram.com/adi__krish/)
