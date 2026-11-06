package main

import (
 "bytes"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "encoding/pem"
 "math"
 "net"
 "net/http"
 "net/http/httptest"
 "net/url"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/gorilla/websocket"
)

type record struct{Kind,Button string; X,Y int32; Key uint16; Units []uint16}
type recorder struct{mu sync.Mutex; Records []record}
func(d *recorder)add(r record)error{d.mu.Lock();defer d.mu.Unlock();d.Records=append(d.Records,r);return nil}
func(d *recorder)Move(x,y int32)error{return d.add(record{Kind:"move",X:x,Y:y})}
func(d *recorder)Click(b string)error{return d.add(record{Kind:"click",Button:b})}
func(d *recorder)Scroll(v int32)error{return d.add(record{Kind:"scroll",Y:v})}
func(d *recorder)Key(v uint16)error{return d.add(record{Kind:"key",Key:v})}
func(d *recorder)Text(v []uint16)error{return d.add(record{Kind:"text",Units:v})}
func(d *recorder)records()[]record{d.mu.Lock();defer d.mu.Unlock();return append([]record(nil),d.Records...)}

func testServer(t *testing.T)(*app,*httptest.Server,*recorder){
 t.Helper();d:=&recorder{};a:=newApp(d,false);a.ips=[]net.IP{net.ParseIP("127.0.0.1")}
 s:=httptest.NewUnstartedServer(a.secureHandler());s.StartTLS();t.Cleanup(s.Close)
 u,_:=url.Parse(s.URL);a.httpsPort,_=strconv.Atoi(u.Port());return a,s,d
}
func pairRequest(t *testing.T,s *httptest.Server,pin,origin string)*http.Response{
 t.Helper();body,_:=json.Marshal(map[string]string{"pin":pin})
 r,_:=http.NewRequest("POST",s.URL+"/api/pair",bytes.NewReader(body));r.Header.Set("Content-Type","application/json");if origin!=""{r.Header.Set("Origin",origin)}
 res,e:=s.Client().Do(r);if e!=nil{t.Fatal(e)};t.Cleanup(func(){res.Body.Close()});return res
}
func pairedCookie(t *testing.T,a *app,s *httptest.Server)*http.Cookie{
 t.Helper();r:=pairRequest(t,s,a.pin,s.URL);if r.StatusCode!=200{t.Fatalf("pair status %d",r.StatusCode)};return r.Cookies()[0]
}
func dial(t *testing.T,s *httptest.Server,cookie *http.Cookie)(*websocket.Conn,*http.Response,error){
 t.Helper();d:=websocket.Dialer{TLSClientConfig:s.Client().Transport.(*http.Transport).TLSClientConfig}
 h:=http.Header{"Origin":[]string{s.URL}};if cookie!=nil{h.Set("Cookie",cookie.String())}
 return d.Dial("wss"+strings.TrimPrefix(s.URL,"https")+"/ws",h)
}
func readMessage(t *testing.T,c *websocket.Conn)map[string]any{
 t.Helper();_ = c.SetReadDeadline(time.Now().Add(2*time.Second));var m map[string]any;if e:=c.ReadJSON(&m);e!=nil{t.Fatal(e)};return m
}

func TestPairingRequiresPINOriginAndSecureCookie(t *testing.T){
 a,s,_:=testServer(t)
 for _,origin:=range []string{"","https://evil.example","http://"+strings.TrimPrefix(s.URL,"https://")}{
  if r:=pairRequest(t,s,a.pin,origin);r.StatusCode!=403{t.Fatalf("accepted origin %q",origin)}
 }
 if r:=pairRequest(t,s,"wrong",s.URL);r.StatusCode!=401{t.Fatal("accepted wrong PIN")}
 c:=pairedCookie(t,a,s)
 if !c.Secure||!c.HttpOnly||c.SameSite!=http.SameSiteStrictMode||len(c.Value)!=64{t.Fatal("unsafe session cookie")}
}
func TestPairingRateLimit(t *testing.T){
 a,s,_:=testServer(t)
 for i:=0;i<12;i++{pairRequest(t,s,"no",s.URL)}
 if r:=pairRequest(t,s,a.pin,s.URL);r.StatusCode!=429{t.Fatal("missing attempt limit")}
}
func TestRejectUnauthenticatedSocket(t *testing.T){
 _,s,_:=testServer(t);c,r,e:=dial(t,s,nil);if c!=nil{c.Close()};if e==nil||r==nil||r.StatusCode!=401{t.Fatal("unauthenticated websocket accepted")}
}
func TestWebsocketRealProtocolToInputDriver(t *testing.T){
 a,s,d:=testServer(t);c,_,e:=dial(t,s,pairedCookie(t,a,s));if e!=nil{t.Fatal(e)};defer c.Close()
 if m:=readMessage(t,c);m["type"]!="hello"||m["realInput"]!=false{t.Fatal(m)}
 commands:=[]Command{{Type:"move",DX:10000,DY:-12.6},{Type:"click",Button:"right"},{Type:"scroll",Amount:120},{Type:"key",Key:"play_pause"},{Type:"text",Text:"Hi 🌿"},{Type:"ping",ID:42}}
 for _,cmd:=range commands{if e:=c.WriteJSON(cmd);e!=nil{t.Fatal(e)}}
 if m:=readMessage(t,c);m["type"]!="pong"||m["id"]!=float64(42){t.Fatal(m)}
 records:=d.records();if len(records)!=5{t.Fatal(records)}
 if records[0].X!=500||records[0].Y!=-13{t.Fatal("movement clamping failed",records[0])}
 if records[1].Button!="right"||records[3].Key!=0xB3||len(records[4].Units)!=5{t.Fatal(records)}
}
func TestLogoutRevokesExistingSocket(t *testing.T){
 a,s,_:=testServer(t);cookie:=pairedCookie(t,a,s);c,_,e:=dial(t,s,cookie);if e!=nil{t.Fatal(e)};defer c.Close();readMessage(t,c)
 r,_:=http.NewRequest("POST",s.URL+"/api/logout",nil);r.Header.Set("Origin",s.URL);r.AddCookie(cookie)
 res,e:=s.Client().Do(r);if e!=nil{t.Fatal(e)};res.Body.Close()
 _ = c.WriteJSON(Command{Type:"ping"});if m:=readMessage(t,c);m["type"]!="expired"{t.Fatal(m)}
}
func TestSecondRemoteTakesOver(t *testing.T){
 a,s,_:=testServer(t);cookie:=pairedCookie(t,a,s);c1,_,e:=dial(t,s,cookie);if e!=nil{t.Fatal(e)};defer c1.Close();readMessage(t,c1)
 c2,_,e:=dial(t,s,cookie);if e!=nil{t.Fatal(e)};defer c2.Close();readMessage(t,c2)
 _ = c1.SetReadDeadline(time.Now().Add(time.Second));_,_,e=c1.ReadMessage()
 if !websocket.IsCloseError(e,4001){t.Fatalf("expected takeover close, got %v",e)}
}
func TestRejectCrossOriginSocketAndRebinding(t *testing.T){
 a,s,_:=testServer(t);cookie:=pairedCookie(t,a,s)
 d:=websocket.Dialer{TLSClientConfig:s.Client().Transport.(*http.Transport).TLSClientConfig}
 c,r,e:=d.Dial("wss"+strings.TrimPrefix(s.URL,"https")+"/ws",http.Header{"Origin":[]string{"https://evil.example"},"Cookie":[]string{cookie.String()}})
 if c!=nil{c.Close()};if e==nil||r.StatusCode!=403{t.Fatal("cross-origin socket accepted")}
 req,_:=http.NewRequest("GET",s.URL+"/",nil);req.Host="evil.example:"+strconv.Itoa(a.httpsPort);res,e:=s.Client().Do(req);if e!=nil{t.Fatal(e)};res.Body.Close();if res.StatusCode!=403{t.Fatal("DNS rebinding allowed")}
}
func TestDispatchRejectsUnsupportedOrInvalidInput(t *testing.T){
 d:=&recorder{}
 for _,c:=range []Command{{Type:"shell",Text:"cmd"},{Type:"key",Key:"arbitrary"},{Type:"click",Button:"middle"},{Type:"move",DX:math.Inf(1)},{Type:"scroll",Amount:math.NaN()},{Type:"text",Text:strings.Repeat("a",257)}}{
  if dispatch(d,c)==nil{t.Fatalf("accepted %#v",c)}
 }
 if len(d.records())!=0{t.Fatal("invalid command produced input")}
}
func TestPlainServerNeverExposesPairingToLAN(t *testing.T){
 a:=newApp(&recorder{},false);a.httpPort=43110;a.ips=[]net.IP{net.ParseIP("192.168.1.20")}
 r:=httptest.NewRequest("GET","http://192.168.1.20:43110/?admin="+a.adminKey,nil);r.RemoteAddr="192.168.1.30:1234"
 w:=httptest.NewRecorder();a.plainHandler().ServeHTTP(w,r)
 if strings.Contains(w.Body.String(),a.pin){t.Fatal("PIN leaked to network")}
}
func TestCertificateReuseRenewalAndNoRootKey(t *testing.T){
 dir:=t.TempDir();ips:=[]net.IP{net.ParseIP("192.168.1.20"),net.ParseIP("127.0.0.1")}
 c,e:=prepareCertificate(dir,ips);if e!=nil{t.Fatal(e)}
 root,e:=x509.ParseCertificate(c.RootDER);if e!=nil{t.Fatal(e)}
 leafPEM,_:=os.ReadFile(c.CertFile);b,_:=pem.Decode(leafPEM);leaf,e:=x509.ParseCertificate(b.Bytes);if e!=nil{t.Fatal(e)}
 pool:=x509.NewCertPool();pool.AddCert(root)
 if _,e=leaf.Verify(x509.VerifyOptions{DNSName:"192.168.1.20",Roots:pool});e!=nil{t.Fatal(e)}
 if _,e=tls.LoadX509KeyPair(c.CertFile,c.KeyFile);e!=nil{t.Fatal(e)}
 again,e:=prepareCertificate(dir,ips);if e!=nil||again.Fingerprint!=c.Fingerprint{t.Fatal("certificate not reused")}
 renewed,e:=prepareCertificate(dir,append(ips,net.ParseIP("192.168.1.21")));if e!=nil||renewed.Fingerprint==c.Fingerprint{t.Fatal("IP change not renewed")}
 files,_:=os.ReadDir(dir);if len(files)!=3{t.Fatal("unexpected secret file persisted")}
 for _,file:=range files{if strings.Contains(file.Name(),"root")&&filepath.Ext(file.Name())!=".cer"{t.Fatal("root key persisted")}}
 if !strings.Contains(c.profile(),"com.apple.security.root")||strings.Contains(c.profile(),"com.apple.mdm"){t.Fatal("bad profile")}
}

func TestDashboardSetupAndCertificateProfile(t *testing.T){
 a:=newApp(&recorder{},false);a.httpPort=43110;a.httpsPort=43111
 a.ips=[]net.IP{net.ParseIP("192.168.1.20"),net.ParseIP("127.0.0.1")}
 var e error;a.cert,e=prepareCertificate(t.TempDir(),a.ips);if e!=nil{t.Fatal(e)}
 cases:=[]struct{path,remote,contains string}{
  {"/?admin="+a.adminKey,"127.0.0.1:1234",a.pin},
  {"/setup?key="+a.setupKey,"192.168.1.30:1234","https://192.168.1.20:43111/"},
  {"/AirGlide.mobileconfig?key="+a.setupKey,"192.168.1.30:1234","com.apple.security.root"},
 }
 for _,tt:=range cases{
  r:=httptest.NewRequest("GET","http://192.168.1.20:43110"+tt.path,nil);r.RemoteAddr=tt.remote
  w:=httptest.NewRecorder();a.plainHandler().ServeHTTP(w,r)
  if w.Code!=200||!strings.Contains(w.Body.String(),tt.contains)||strings.Contains(w.Body.String(),"ZgotmplZ"){t.Fatalf("render failed: %s",tt.path)}
 }
 r:=httptest.NewRequest("GET","http://192.168.1.20:43110/qr?admin="+a.adminKey,nil);r.RemoteAddr="127.0.0.1:1234"
 w:=httptest.NewRecorder();a.plainHandler().ServeHTTP(w,r)
 if w.Header().Get("Content-Type")!="image/png"||!bytes.HasPrefix(w.Body.Bytes(),[]byte{137,80,78,71}){t.Fatal("QR generation failed")}
}
