package f5

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmcvetta/napping"
)

var (
	// Underlying transports/clients
	tsport            http.Transport
	hsport            http.Transport
	clnt              http.Client
	headers           http.Header
	debug             bool // kept for API compatibility, but not used for logging
	tokenMutex        = sync.Mutex{}
	stats_path_prefix string
)

const (
	GET = iota
	POST
	POSTR
	PUT
	PUTR
	PATCH
	DELETE
)

type httperr struct {
	Message string
	Errors  []struct {
		Resource string
		Field    string
		Code     string
	}
}

type Device struct {
	Hostname        string
	Username        string
	Password        string
	Session         napping.Session
	AuthToken       authToken
	AuthMethod      AuthMethod
	Proto           string
	StatsPathPrefix string
	StatsShowZeroes bool
}

type Response struct {
	Status  int
	Message string
}

type LBEmptyBody struct{}

type LBTransaction struct {
	TransId int    `json:"transId"`
	Timeout int    `json:"timeoutSeconds"`
	State   string `json:"state"`
}

type LBTransactionState struct {
	State string `json:"state"`
}

type AuthMethod int

const (
	TOKEN AuthMethod = iota
	BASIC_AUTH
)

type authToken struct {
	Token            string
	ExpirationMicros int64
}

// ---------- logging transport ------------------------------------------------

type LoggingTransport struct {
	Base http.RoundTripper
}

func (lt *LoggingTransport) base() http.RoundTripper {
	if lt.Base != nil {
		return lt.Base
	}
	return http.DefaultTransport
}

func (lt *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Clone body for logging + restore for downstream
	var reqBody []byte
	if req.Body != nil {
		var err error
		reqBody, err = io.ReadAll(req.Body)
		if err != nil {
			log.Printf("[HTTP] ERROR reading request body: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	log.Printf("[HTTP] --> %s %s", req.Method, req.URL.String())
	logHeaders("Request", req.Header)
	if len(reqBody) > 0 {
		logBody("Request", req.Header.Get("Content-Type"), reqBody)
	} else {
		log.Printf("[HTTP]     (no request body)")
	}

	resp, err := lt.base().RoundTrip(req)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("[HTTP] !!  ERROR %s %s after %s: %v", req.Method, req.URL.String(), elapsed, err)
		return nil, err
	}

	// Read/clone response body for logging
	var respBody []byte
	if resp.Body != nil {
		var rerr error
		respBody, rerr = io.ReadAll(resp.Body)
		if rerr != nil {
			log.Printf("[HTTP] ERROR reading response body: %v", rerr)
		}
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}

	log.Printf("[HTTP] <-- %s %s %d (%s)", req.Method, req.URL.String(), resp.StatusCode, elapsed)
	if resp.TLS != nil {
		cs := resp.TLS
		log.Printf("[HTTP]     TLS: vers=%x cipher=%x proto=%s resumed=%v",
			cs.Version, cs.CipherSuite, cs.NegotiatedProtocol, cs.DidResume)
	}
	logHeaders("Response", resp.Header)
	if len(respBody) > 0 {
		ct := resp.Header.Get("Content-Type")
		logBody("Response", ct, respBody)
	} else {
		log.Printf("[HTTP]     (no response body)")
	}

	return resp, nil
}

func logHeaders(prefix string, h http.Header) {
	// Sort keys for stable output
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := h.Values(k)
		log.Printf("[HTTP]     %s-H %s: %s", prefix, k, strings.Join(vs, ", "))
	}
}

func logBody(prefix, contentType string, b []byte) {
	if isLikelyJSON(contentType, b) {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, b, "", "  "); err == nil {
			log.Printf("[HTTP]     %s-Body (JSON):\n%s", prefix, pretty.String())
			return
		}
	}
	// Fallback: raw text (trim very long bodies to keep logs manageable)
	const max = 1 << 20 // 1 MiB cap
	if len(b) > max {
		log.Printf("[HTTP]     %s-Body (%s, %d bytes, truncated to %d):\n%s",
			prefix, printableCT(contentType), len(b), max, string(b[:max]))
	} else {
		log.Printf("[HTTP]     %s-Body (%s, %d bytes):\n%s",
			prefix, printableCT(contentType), len(b), string(b))
	}
}

func isLikelyJSON(ct string, b []byte) bool {
	ct = strings.ToLower(ct)
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "application/vnd") {
		return true
	}
	trim := bytes.TrimSpace(b)
	return len(trim) > 0 && (trim[0] == '{' || trim[0] == '[')
}

func printableCT(ct string) string {
	if ct == "" {
		return "unknown"
	}
	return ct
}

// ---------- public API -------------------------------------------------------

func New(host string, username string, pwd string, authMethod AuthMethod) *Device {
	f := Device{Hostname: host, Username: username, Password: pwd, AuthMethod: authMethod, Proto: "https", StatsPathPrefix: "f5.", StatsShowZeroes: false}
	f.InitSession()
	return &f
}

func NewInsecure(host string, username string, pwd string, authMethod AuthMethod) *Device {
	f := Device{Hostname: host, Username: username, Password: pwd, AuthMethod: authMethod, Proto: "http", StatsPathPrefix: "f5.", StatsShowZeroes: false}
	f.InitSession()
	return &f
}

func (f *Device) InitSession() {
	// REST connection setup
	if f.Proto == "https" {
		tsport = http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		}
		clnt = http.Client{Transport: &LoggingTransport{Base: &tsport}}
	} else {
		hsport = http.Transport{
			Proxy: http.ProxyFromEnvironment,
		}
		clnt = http.Client{Transport: &LoggingTransport{Base: &hsport}}
	}
	headers = make(http.Header)

	// Setup HTTP Basic auth for this session (ONLY use this with SSL). Auth can
	// also be configured per-request when using Send().
	f.Session = napping.Session{
		Client:   &clnt,
		Log:      false, // transport handles all logging unconditionally
		Userinfo: url.UserPassword(f.Username, f.Password),
		Header:   &headers,
	}
}

func (f *Device) SetDebug(b bool) {
	// Kept for compatibility; no longer controls logging
	debug = b
}

func (f *Device) SetTokenAuth(t bool) {
	debugout := "TOKEN_AUTH"
	if t {
		f.AuthMethod = TOKEN
	} else {
		f.AuthMethod = BASIC_AUTH
		debugout = "BASIC_AUTH"
	}
	if debug {
		fmt.Printf("authentication mode: %s\n", debugout)
	}
}

func (f *Device) SetStatsPathPrefix(p string) {
	if strings.HasSuffix(p, ".") {
		f.StatsPathPrefix = p
	} else {
		f.StatsPathPrefix = p + "."
	}
}
func (f *Device) SetStatsShowZeroes(b bool) {
	f.StatsShowZeroes = b
}

func (f *Device) StartTransaction() (error, string) {
	u := f.Proto + "://" + f.Hostname + "/mgmt/tm/transaction"
	empty := LBEmptyBody{}
	tres := LBTransaction{}
	err, _ := f.sendRequest(u, POST, &empty, &tres)
	if err != nil {
		return err, ""
	}

	tid := fmt.Sprintf("%d", tres.TransId)
	// set the transaction header
	f.Session.Header.Set("X-F5-REST-Coordination-Id", tid)
	return nil, tid
}

func (f *Device) CommitTransaction(tid string) error {
	// remove the transaction header first
	f.Session.Header.Del("X-F5-REST-Coordination-Id")

	u := f.Proto + "://" + f.Hostname + "/mgmt/tm/transaction/" + tid
	body := LBTransaction{State: "VALIDATING"}
	tres := LBTransaction{}
	err, _ := f.sendRequest(u, PATCH, &body, &tres)
	if err != nil {
		return err
	}
	return nil
}

func (f *Device) sendRequest(u string, method int, pload interface{}, res interface{}) (error, *Response) {
	if f.AuthMethod == TOKEN {
		f.ensureValidToken()
	}

	// Send request
	e := httperr{}
	var (
		err   error
		nresp *napping.Response
	)

	switch method {
	case GET:
		nresp, err = f.Session.Get(u, nil, &res, &e)
	case POST:
		nresp, err = f.Session.Post(u, &pload, &res, &e)
	case PUT:
		nresp, err = f.Session.Put(u, &pload, &res, &e)
	case PATCH:
		nresp, err = f.Session.Patch(u, &pload, &res, &e)
	case DELETE:
		nresp, err = f.Session.Delete(u, nil, &res, &e)
	case POSTR:
		r := napping.Request{
			Method:     "POST",
			Url:        u,
			Params:     nil,
			Payload:    pload,
			RawPayload: true,
			Result:     res,
			Error:      e,
		}
		nresp, err = f.Session.Send(&r)
	case PUTR:
		r := napping.Request{
			Method:     "PUT",
			Url:        u,
			Params:     nil,
			Payload:    pload,
			RawPayload: true,
			Result:     &res,
			Error:      &e,
		}
		nresp, err = f.Session.Send(&r)
	}

	var resp Response
	if nresp != nil {
		resp = Response{Status: nresp.Status(), Message: e.Message}
	}

	if err != nil {
		return err, &resp
	}
	if nresp.Status() == 401 {
		f.PrintObject(resp)
		return errors.New("error: 401 Unauthorised - check your username and passwd"), &resp
	}
	if nresp.Status() >= 300 {
		return errors.New(e.Message), &resp
	}
	// all is good
	return nil, &resp
}

func (f *Device) PrintObject(input interface{}) {
	jsonresp, err := json.MarshalIndent(&input, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(jsonresp))
}

// F5 Module data struct
// to show all available modules when using show without args
type LBModule struct {
	Link string `json:"link"`
}

type LBModuleRef struct {
	Reference LBModule `json:"reference"`
}

type LBModules struct {
	Items []LBModuleRef `json:"items"`
}

func (f *Device) ShowModules() (error, *LBModules) {
	ltmUrl := f.Proto + "://" + f.Hostname + "/mgmt/tm/ltm"
	sysUrl := f.Proto + "://" + f.Hostname + "/mgmt/tm/sys"

	// Containers for responses
	ltmResponse := LBModules{}
	sysResponse := LBModules{} // Assuming /mgmt/tm/sys has the same format

	// First request to /mgmt/tm/ltm
	err, _ := f.sendRequest(ltmUrl, GET, nil, &ltmResponse)
	if err != nil {
		return err, nil
	}

	// Second request to /mgmt/tm/sys
	err, _ = f.sendRequest(sysUrl, GET, nil, &sysResponse)
	if err != nil {
		return err, nil
	}

	// Combine the results into one array
	combinedItems := append(ltmResponse.Items, sysResponse.Items...)

	// Return the combined result
	return nil, &LBModules{Items: combinedItems}
}

func (f *Device) GetToken() {
	type login struct {
		Token struct {
			Token            string `json:"token"`
			ExpirationMicros int64  `json:"expirationMicros"`
		} `json:"token"`
	}

	LoginData := map[string]string{"username": f.Username, "password": f.Password, "loginProviderName": "tmos"}
	byteLogin, err := json.Marshal(LoginData)
	body := json.RawMessage(byteLogin)
	u := f.Proto + "://" + f.Hostname + "/mgmt/shared/authn/login"
	res := login{}
	e := httperr{}

	resp, err := f.Session.Post(u, &body, &res, &e)
	if err != nil {
		log.Fatal(fmt.Errorf("error: %s, %v", err, resp))
		return
	}

	f.AuthToken = authToken{
		Token:            res.Token.Token,
		ExpirationMicros: res.Token.ExpirationMicros,
	}
	f.Session.Header.Set("X-F5-Auth-Token", f.AuthToken.Token)

	// disable basic auth now
	f.Session.Userinfo = nil
}

func (f *Device) hasValidToken() bool {
	nowMicros := time.Now().UnixNano() / (int64(time.Microsecond) / int64(time.Nanosecond))
	if f.AuthToken.Token == "" || f.AuthToken.ExpirationMicros < nowMicros+int64(time.Millisecond)*100 {
		return false
	}
	return true
}

func (f *Device) ensureValidToken() {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	if !f.hasValidToken() {
		f.GetToken()
	}
}
