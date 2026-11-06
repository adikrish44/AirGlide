package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	qrcode "github.com/skip2/go-qrcode"
)

//go:embed web/*
var assets embed.FS

const version = "1.3.0"

type session struct{ Expires time.Time }
type limiter struct {
	At    time.Time
	Count int
}
type app struct {
	mu                            sync.Mutex
	inputMu                       sync.Mutex
	driver                        InputDriver
	realInput                     bool
	name, pin, adminKey, setupKey string
	cert                          Certificate
	ips                           []net.IP
	httpPort, httpsPort           int
	sessions                      map[string]session
	attempts                      limiter
	active                        *websocket.Conn
}

func newApp(d InputDriver, real bool) *app {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		panic(err)
	}
	name, _ := os.Hostname()
	if name == "" {
		name = "Windows PC"
	}
	return &app{driver: d, realInput: real, name: name, pin: fmt.Sprintf("%06d", n.Int64()), adminKey: randomHex(24), setupKey: randomHex(24), sessions: make(map[string]session)}
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func clientIP(r *http.Request) net.IP {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return nil
	}
	return net.ParseIP(h)
}
func localClient(r *http.Request) bool {
	ip := clientIP(r)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}
func loopback(r *http.Request) bool { ip := clientIP(r); return ip != nil && ip.IsLoopback() }
func (a *app) validHost(host string, port int) bool {
	h, p, e := net.SplitHostPort(host)
	if e != nil || p != fmt.Sprint(port) {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	for _, v := range a.ips {
		if ip.Equal(v) {
			return true
		}
	}
	return false
}
func (a *app) sameOrigin(r *http.Request) bool {
	u, e := url.Parse(r.Header.Get("Origin"))
	return e == nil && u.Scheme == "https" && u.Host == r.Host && a.validHost(r.Host, a.httpsPort)
}
func (a *app) authenticated(r *http.Request) bool {
	c, e := r.Cookie("airremote_session")
	if e != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if ok && time.Now().Before(s.Expires) {
		return true
	}
	delete(a.sessions, c.Value)
	return false
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (a *app) pair(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || !a.sameOrigin(r) {
		http.Error(w, "Use the remote app to pair", 403)
		return
	}
	a.mu.Lock()
	now := time.Now()
	if now.Sub(a.attempts.At) > time.Minute {
		a.attempts = limiter{At: now}
	}
	a.attempts.Count++
	blocked := a.attempts.Count > 12
	a.mu.Unlock()
	if blocked {
		respond(w, 429, map[string]string{"error": "Too many attempts. Wait one minute."})
		return
	}
	var p struct {
		PIN string `json:"pin"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 256)).Decode(&p) != nil || !equal(p.PIN, a.pin) {
		respond(w, 401, map[string]string{"error": "That code does not match. Check the PC window."})
		return
	}
	token := randomHex(32)
	expires := now.Add(12 * time.Hour)
	a.mu.Lock()
	for k, v := range a.sessions {
		if now.After(v.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 8 {
		a.mu.Unlock()
		respond(w, 429, map[string]string{"error": "Too many paired sessions. Restart the companion to reset them."})
		return
	}
	a.sessions[token] = session{expires}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "airremote_session", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 60 * 60})
	respond(w, 200, map[string]any{"name": a.name, "realInput": a.realInput})
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || !a.sameOrigin(r) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if c, e := r.Cookie("airremote_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "airremote_session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *app) socket(w http.ResponseWriter, r *http.Request) {
	if !a.authenticated(r) {
		http.Error(w, "Pair first", 401)
		return
	}
	u := websocket.Upgrader{CheckOrigin: a.sameOrigin, HandshakeTimeout: 5 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096}
	c, e := u.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	defer c.Close()
	a.mu.Lock()
	previous := a.active
	a.active = c
	a.mu.Unlock()
	if previous != nil {
		_ = previous.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "Another remote connected"), time.Now().Add(time.Second))
		_ = previous.Close()
	}
	defer func() {
		a.mu.Lock()
		if a.active == c {
			a.active = nil
		}
		a.mu.Unlock()
	}()
	c.SetReadLimit(4096)
	write := func(v any) error { _ = c.SetWriteDeadline(time.Now().Add(2 * time.Second)); return c.WriteJSON(v) }
	if write(map[string]any{"type": "hello", "name": a.name, "realInput": a.realInput, "version": version}) != nil {
		return
	}
	window := time.Now()
	count := 0
	for {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		var cmd Command
		if c.ReadJSON(&cmd) != nil {
			return
		}
		if !a.authenticated(r) {
			_ = write(map[string]string{"type": "expired"})
			return
		}
		if time.Since(window) > time.Second {
			window = time.Now()
			count = 0
		}
		count++
		if count > 240 {
			return
		}
		if cmd.Type == "ping" {
			if write(map[string]any{"type": "pong", "id": cmd.ID}) != nil {
				return
			}
			continue
		}
		a.inputMu.Lock()
		a.mu.Lock()
		isActive := a.active == c
		a.mu.Unlock()
		if !isActive {
			a.inputMu.Unlock()
			return
		}
		err := dispatch(a.driver, cmd)
		a.inputMu.Unlock()
		if err != nil {
			if write(map[string]string{"type": "error", "message": err.Error()}) != nil {
				return
			}
		}
	}
}
func (a *app) secureHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/pair", a.pair)
	mux.HandleFunc("/api/logout", a.logout)
	mux.HandleFunc("/ws", a.socket)
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if !a.authenticated(r) {
			respond(w, 401, map[string]bool{"paired": false})
			return
		}
		respond(w, 200, map[string]any{"paired": true, "name": a.name, "realInput": a.realInput})
	})
	web, _ := fs.Sub(assets, "web")
	files := http.FileServer(http.FS(web))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := map[string]bool{"/": true, "/index.html": true, "/style.css": true, "/app.js": true, "/motion.js": true, "/manifest.webmanifest": true, "/icon.svg": true, "/icon.svg": true, "/icon-192.png": true, "/icon-512.png": true, "/apple-touch-icon.png": true, "/sw.js": true}
		if !allowed[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !localClient(r) || !a.validHost(r.Host, a.httpsPort) {
			http.Error(w, "Local network only", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss://"+r.Host+"; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), accelerometer=(self), gyroscope=(self), magnetometer=()")
		mux.ServeHTTP(w, r)
	})
}

const pageCSS = `body{margin:0;background:#0d1117;color:#edf2f7;font:16px/1.6 system-ui,-apple-system,sans-serif}main{max-width:780px;margin:auto;padding:44px 24px}h1{font-size:40px;letter-spacing:-1.5px;line-height:1.1;margin:12px 0}h2{font-size:22px}p{color:#bac6d4}a{color:#8fdcca;word-break:break-all}.card{background:#171f2a;border:1px solid #303b49;border-radius:22px;padding:24px;margin:20px 0}.tag{font-size:12px;letter-spacing:2px;color:#8fdcca}.pin{font-size:48px;font-weight:650;letter-spacing:10px;font-variant-numeric:tabular-nums}.qr{width:210px;height:210px;background:white;border-radius:12px;display:block;margin:20px 0}.btn{display:inline-block;text-decoration:none;background:#a6ead9;color:#10211d;border-radius:12px;padding:12px 20px;font-weight:650}small{color:#9baabc}code{font-family:ui-monospace,monospace;word-break:break-all}li{margin:12px 0}.fingerprint{font-size:12px;word-break:break-all}strong{color:#edf2f7}.row{display:flex;gap:28px;flex-wrap:wrap}details{margin-top:20px}`

func renderPage(w http.ResponseWriter, t string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl := template.Must(template.New("page").Parse(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>AirGlide setup</title><style>` + pageCSS + `.creator{margin:22px 0 8px;color:#a8bdc3;font-size:12px;line-height:1.7}.creator strong{color:#edf3f0}.creator a{color:#abe4cd;text-decoration:underline;text-underline-offset:3px}.airglide-logo{display:block;width:96px;height:auto;margin-bottom:18px}` + `</style></head><body><main><img class="airglide-logo" src="/icon.svg" alt="AirGlide">` + t + `<footer class="creator">Created by <strong>Aditya Krishna Thota</strong> · <a href="https://www.instagram.com/adi__krish/" target="_blank" rel="noopener noreferrer">@adi__krish</a> · <a href="https://www.instagram.com/adi__krish/" target="_blank" rel="noopener noreferrer">Send Feedback</a></footer></main></body></html>`))
	_ = tpl.Execute(w, data)
}

const setupNavigation = `<nav aria-label="Phone setup"><a href="{{.Android}}">Android</a> · <a href="{{.IPhone}}">iPhone</a></nav>`
const iphoneSetup = `<span class="tag">IPHONE SETUP</span><h1>A little setup.<br>A lot less reaching.</h1><p>This connects your iPhone to your own PC. Keep both devices on the same home network.</p><div class="card"><h2>1. Install the local certificate</h2><p>Motion controls need a trusted, encrypted connection. This profile contains only a certificate. It adds no device management or VPN.</p><a class="btn" href="{{.Profile}}">Download certificate profile</a><p>Open <strong>Settings → Profile Downloaded → Install</strong>. If needed, find it under <strong>General → VPN &amp; Device Management</strong>.</p><h2>2. Enable certificate trust</h2><p>Go to <strong>Settings → General → About → Certificate Trust Settings</strong>. Turn on trust for <strong>{{.Name}}</strong>.</p><small>Install only the profile generated by your PC. Compare this SHA-256 fingerprint with the PC window:</small><p class="fingerprint"><code>{{.Fingerprint}}</code></p></div><div class="card"><h2>3. Open your remote</h2><a class="btn" href="{{.Remote}}">Open AirGlide</a><p>Enter the six-digit code shown on Windows. In Safari, choose <strong>Share → Add to Home Screen</strong> and enable <strong>Open as Web App</strong> if shown. Pair again from the Home Screen app if asked, then tap <strong>Enable motion</strong>.</p><p>Hold the phone in portrait with its top edge aimed toward the screen. Keep the app open while controlling the PC.</p></div><p>To remove later: delete the Home Screen app and remove this certificate profile in Settings.</p>`
const androidSetup = `<h1>Connect your Android phone</h1>
<p>Keep the phone and Windows PC on the same home network. Open this page in Chrome.</p>
<section class="card"><h2>1. Download your PC’s certificate</h2>
<a class="btn" href="{{.Certificate}}">Download AirGlide-Local.crt</a>
<p>The certificate name is <strong>{{.Name}}</strong>. Verify the downloaded certificate’s SHA-256 fingerprint against the PC dashboard before trusting it.</p>
<p class="fingerprint"><code>{{.Fingerprint}}</code></p></section>
<section class="card"><h2>2. Install the CA certificate</h2>
<p>Open Android Settings and search for <strong>Install a certificate</strong>. Under <strong>Encryption &amp; credentials</strong>, choose <strong>Install a certificate → CA certificate</strong>. Select <strong>AirGlide-Local.crt</strong> from Downloads. Menu names vary by phone.</p>
<p>This adds a trusted root to your phone. Only install the certificate from your own PC. To remove it later, select this certificate under user-installed trusted credentials.</p></section>
<section class="card"><h2>3. Pair your remote</h2><a class="btn" href="{{.Remote}}">Open AirGlide</a>
<p>Enter the six-digit code from Windows. Tap <strong>Enable motion</strong>, then point the top edge of your phone toward the screen. Choose <strong>Touchpad</strong> if your phone has no usable motion sensor.</p>
<p>To keep AirGlide on your Home screen, use the Chrome menu and choose <strong>Install app</strong> or <strong>Add to Home screen</strong>. If Chrome offers a choice between installing and creating a shortcut, choose Install.</p></section>`

func (a *app) setupURL(ip net.IP) string {
	return fmt.Sprintf("http://%s:%d/setup?key=%s", ip, a.httpPort, a.setupKey)
}
func (a *app) remoteURL(ip net.IP) string { return fmt.Sprintf("https://%s:%d/", ip, a.httpsPort) }
func (a *app) plainHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !localClient(r) || !a.validHost(r.Host, a.httpPort) {
			http.Error(w, "Local network only", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		ip := a.ips[0]
		if s := r.URL.Query().Get("ip"); s != "" {
			for _, p := range a.ips {
				if p.String() == s {
					ip = p
				}
			}
		} else if h, _, e := net.SplitHostPort(r.Host); e == nil {
			for _, p := range a.ips {
				if p.String() == h && !p.IsLoopback() {
					ip = p
				}
			}
		}
		if r.URL.Path == "/icon.svg" {
			w.Header().Set("Content-Type", "image/png")
			data, _ := assets.ReadFile("web/icon.svg")
			_, _ = w.Write(data)
			return
		}
		if r.URL.Path == "/setup" || r.URL.Path == "/AirGlide.mobileconfig" || r.URL.Path == "/AirGlide-Local.crt" {
			if !equal(r.URL.Query().Get("key"), a.setupKey) {
				http.Error(w, "Scan the current QR code on your PC", 403)
				return
			}
			if r.URL.Path == "/AirGlide-Local.crt" {
				w.Header().Set("Content-Type", "application/x-x509-ca-cert")
				w.Header().Set("Content-Disposition", `attachment; filename="AirGlide-Local.crt"`)
				_, _ = w.Write(a.cert.RootDER)
				return
			}
			if r.URL.Path == "/AirGlide.mobileconfig" {
				w.Header().Set("Content-Type", "application/x-apple-aspen-config")
				w.Header().Set("Content-Disposition", `attachment; filename="AirGlide.mobileconfig"`)
				_, _ = w.Write([]byte(a.cert.profile()))
				return
			}
			platform := r.URL.Query().Get("platform")
			android := platform == "android" || (platform == "" && strings.Contains(strings.ToLower(r.UserAgent()), "android"))
			instructions := iphoneSetup
			if android {
				instructions = androidSetup
			}
			renderPage(w, setupNavigation+instructions, map[string]string{
				"Android":     "/setup?platform=android&key=" + a.setupKey,
				"IPhone":      "/setup?platform=iphone&key=" + a.setupKey,
				"Certificate": "/AirGlide-Local.crt?key=" + a.setupKey,
				"Profile":     "/AirGlide.mobileconfig?key=" + a.setupKey,
				"Name":        a.cert.Name, "Fingerprint": a.cert.Fingerprint, "Remote": a.remoteURL(ip),
			})
			return
		}
		if !loopback(r) || !equal(r.URL.Query().Get("admin"), a.adminKey) {
			renderPage(w, `<span class="tag">AIRGLIDE</span><h1>Open the PC companion.</h1><p>Scan the setup QR code shown on your Windows PC.</p>`, nil)
			return
		}
		if r.URL.Path == "/qr" {
			target := a.setupURL(ip)
			if r.URL.Query().Get("kind") == "remote" {
				target = a.remoteURL(ip)
			}
			png, e := qrcode.Encode(target, qrcode.Medium, 360)
			if e != nil {
				http.Error(w, "QR unavailable", 500)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
			return
		}
		type address struct{ IP, Dashboard string }
		var addresses []address
		for _, p := range a.ips {
			if !p.IsLoopback() {
				addresses = append(addresses, address{p.String(), "/?admin=" + a.adminKey + "&ip=" + p.String()})
			}
		}
		renderPage(w, `<span class="tag">AIRGLIDE / WINDOWS COMPANION {{.Version}}</span><h1>Your phone.<br>Your pointer.</h1><p>Ready on <strong>{{.PC}}</strong>. Leave the companion window running.</p>{{if not .Real}}<div class="card"><strong>Simulator — no Windows input is being sent.</strong></div>{{end}}<div class="card"><small>PAIRING CODE · CHANGES WHEN YOU RESTART</small><div class="pin">{{.PIN}}</div><p>Only share this code with the person controlling your PC.</p></div><div class="row"><div class="card"><h2>First time?</h2><img class="qr" src="{{.SetupQR}}" alt="Scan to set up AirGlide"><p>Scan with your Android phone or iPhone.</p><a href="{{.Setup}}">Open setup instructions</a></div><div class="card"><h2>Already set up?</h2><img class="qr" src="{{.RemoteQR}}" alt="Scan to open AirGlide"><p>Open your Home Screen app or scan.</p><a href="{{.Remote}}">{{.Remote}}</a></div></div><details><summary>Connection details</summary><p>Phone and PC must use the same local network. The PC may use Ethernet.</p><p>Selected PC address: <strong>{{.IP}}</strong></p>{{range .Addresses}}<p><a href="{{.Dashboard}}">Use {{.IP}}</a></p>{{end}}<p>Certificate: <strong>{{.CertName}}</strong></p><p class="fingerprint"><code>{{.Fingerprint}}</code></p><p>If the PC address changes, restart the companion. If it creates a new certificate, repeat setup on your iPhone and remove the old profile.</p></details><p>Close the console to stop all control and invalidate pairings. The companion has no autostart, cloud relay, screen recording, or remote shell.</p>`, map[string]any{"Version": version, "PC": a.name, "Real": a.realInput, "PIN": a.pin, "SetupQR": "/qr?admin=" + a.adminKey + "&ip=" + ip.String(), "RemoteQR": "/qr?kind=remote&admin=" + a.adminKey + "&ip=" + ip.String(), "Setup": a.setupURL(ip), "Remote": a.remoteURL(ip), "IP": ip.String(), "Addresses": addresses, "CertName": a.cert.Name, "Fingerprint": a.cert.Fingerprint})
	})
}
func localIPs() []net.IP {
	var result []net.IP
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := i.Addrs()
		for _, ad := range addresses {
			ip, _, e := net.ParseCIDR(ad.String())
			if e == nil && ip.To4() != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				result = append(result, ip.To4())
			}
		}
	}
	return append(result, net.IPv4(127, 0, 0, 1))
}
func run() error {
	base, e := os.UserConfigDir()
	if e != nil {
		return e
	}
	state := flag.String("state-dir", filepath.Join(base, "AirRemote"), "Directory for this PC's local TLS files")
	noBrowser := flag.Bool("no-browser", false, "Do not open setup dashboard")
	hp := flag.Int("http-port", 43110, "Local setup port")
	sp := flag.Int("https-port", 43111, "Encrypted remote port")
	flag.Parse()
	if *hp < 1024 || *hp > 65535 || *sp < 1024 || *sp > 65535 || *hp == *sp {
		return errors.New("choose two different ports between 1024 and 65535")
	}
	d, real := newDriver()
	a := newApp(d, real)
	a.httpPort = *hp
	a.httpsPort = *sp
	a.ips = localIPs()
	a.cert, e = prepareCertificate(*state, a.ips)
	if e != nil {
		return fmt.Errorf("prepare local certificate: %w", e)
	}
	pair, e := tls.LoadX509KeyPair(a.cert.CertFile, a.cert.KeyFile)
	if e != nil {
		return e
	}
	l1, e := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", *hp))
	if e != nil {
		return e
	}
	defer l1.Close()
	l2, e := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", *sp))
	if e != nil {
		return e
	}
	defer l2.Close()
	s1 := &http.Server{Handler: a.plainHandler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	s2 := &http.Server{Handler: a.secureHandler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- s1.Serve(l1) }()
	go func() {
		errorsCh <- s2.Serve(tls.NewListener(l2, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}))
	}()
	dashboard := fmt.Sprintf("http://127.0.0.1:%d/?admin=%s", *hp, a.adminKey)
	fmt.Printf("\nAIRGLIDE %s\n\nPC: %s\nPairing code: %s\n\nSetup dashboard:\n%s\n\nKeep this window open. Press Ctrl+C to stop.\n", version, a.name, a.pin, dashboard)
	if !real {
		fmt.Println("SIMULATOR: Windows input is disabled on this operating system.")
	}
	if !*noBrowser {
		openBrowser(dashboard)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	select {
	case <-sig:
	case err := <-errorsCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s1.Shutdown(ctx)
	_ = s2.Shutdown(ctx)
	a.mu.Lock()
	if a.active != nil {
		_ = a.active.Close()
	}
	a.mu.Unlock()
	return nil
}
func main() {
	if e := run(); e != nil {
		log.Printf("AirGlide could not start: %v", e)
		os.Exit(1)
	}
}
