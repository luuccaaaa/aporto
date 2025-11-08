package proxy

import (
	"html/template"
	"net/http"
	"strings"
	"time"
)

const (
	gateConfirmPath  = "/.aporto-visit"
	skipCookieName   = "aporto_skip_warning"
	skipHeaderName   = "X-Skip-Browser-Warning"
	skipCookieMaxAge = 6 * time.Hour
)

var warningPageTemplate = template.Must(template.New("aporto-warning").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta http-equiv="Cache-Control" content="no-store" />
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Visit {{.Host}}</title>
	<style>
		:root { color-scheme: light dark; font-size: 16px; }
		* { box-sizing: border-box; }
		body {
			margin: 0;
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
			background: #f7f7f8;
			color: #0f172a;
			display: grid;
			min-height: 100vh;
			place-items: center;
			padding: 24px;
		}
		.card {
			width: 100%;
			max-width: 420px;
			border-radius: 16px;
			border: 1px solid rgba(15,23,42,0.08);
			background: #ffffff;
			padding: 28px;
			box-shadow: 0 8px 30px rgba(15,23,42,0.08);
			text-align: center;
		}
		h1 { font-size: 1.25rem; margin: 0 0 12px; }
		p { margin: 0 0 16px; color: #475569; line-height: 1.45; }
		button {
			width: 100%;
			border: none;
			border-radius: 8px;
			padding: 12px 16px;
			font-size: 1rem;
			font-weight: 600;
			background: #111827;
			color: #ffffff;
			cursor: pointer;
		}
        button:hover { background: #0f172a; }
		code {
			font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
			padding: 2px 6px;
			border-radius: 4px;
			background: rgba(15,23,42,0.06);
		}
		.tip { font-size: 0.85rem; color: #64748b; margin-top: 20px; }
	</style>
</head>
<body>
	<main class="card">
		<h1>Heads up</h1>
		<p>You're about to open <strong>{{.Host}}</strong>. We show this page once to filter scanners and only pass real browsers through.</p>
		<form method="POST" action="{{.GatePath}}">
			<input type="hidden" name="continue" value="{{.Continue}}">
			<button type="submit">Continue to tunnel</button>
		</form>
		<p class="tip">Automations can set <code>{{.HeaderName}}: true</code> to skip this step.</p>
	</main>
</body>
</html>`))

type warningPageData struct {
	Host       string
	Continue   string
	GatePath   string
	HeaderName string
}

func (p *HTTPProxy) shouldShowWarning(r *http.Request) bool {
	if skipHeaderBypasses(r.Header.Get(skipHeaderName)) {
		return false
	}
	if hasSkipCookie(r) {
		return false
	}
	return true
}

func skipHeaderBypasses(val string) bool {
	if val == "" {
		return false
	}
	v := strings.TrimSpace(strings.ToLower(val))
	return v == "true" || v == "1" || v == "yes"
}

func hasSkipCookie(r *http.Request) bool {
	c, err := r.Cookie(skipCookieName)
	return err == nil && c.Value != ""
}

func (p *HTTPProxy) serveWarningPage(w http.ResponseWriter, r *http.Request, host string) {
	data := warningPageData{
		Host:       host,
		Continue:   sanitizeContinuePath(r.URL.RequestURI()),
		GatePath:   gateConfirmPath,
		HeaderName: skipHeaderName,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := warningPageTemplate.Execute(w, data); err != nil {
		p.log.Error().Err(err).Msg("render warning page")
	}
}

func (p *HTTPProxy) handleGateConfirmation(w http.ResponseWriter, r *http.Request, host string) bool {
	if r.URL.Path != gateConfirmPath {
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	target := sanitizeContinuePath(r.FormValue("continue"))
	http.SetCookie(w, buildSkipCookie(host, r.TLS != nil))
	http.Redirect(w, r, target, http.StatusSeeOther)
	return true
}

func sanitizeContinuePath(in string) string {
	in = strings.TrimSpace(in)
	if in == "" || !strings.HasPrefix(in, "/") {
		return "/"
	}
	if len(in) > 2048 {
		in = in[:2048]
	}
	return in
}

func buildSkipCookie(host string, secure bool) *http.Cookie {
	domain := ""
	if strings.Contains(host, ".") {
		domain = host
	}
	return &http.Cookie{
		Name:     skipCookieName,
		Value:    "1",
		Path:     "/",
		Domain:   domain,
		MaxAge:   int(skipCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
