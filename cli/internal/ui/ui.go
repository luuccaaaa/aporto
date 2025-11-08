package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type UI struct {
	program   *tea.Program
	logWriter *logWriter
	errCh     chan error
}

func New(hostname, local string, dark bool) (*UI, error) {
	m := newModel(hostname, local, dark)
	p := tea.NewProgram(m, tea.WithAltScreen())
	ui := &UI{
		program:   p,
		logWriter: &logWriter{prog: p},
		errCh:     make(chan error, 1),
	}
	go func() {
		if err := p.Start(); err != nil {
			ui.errCh <- err
		}
		close(ui.errCh)
	}()
	return ui, nil
}

func (u *UI) Close() {
	u.program.Quit()
	<-u.errCh
}

func (u *UI) UpdatePublic(host string) {
	u.program.Send(publicMsg(formatURL(host)))
}

func (u *UI) UpdateLocal(local string) {
	u.program.Send(localMsg(fallbackLocal(local)))
}

func (u *UI) SetStatus(status string) {
	u.program.Send(statusMsg(strings.ToUpper(status)))
}

func (u *UI) LogRequest(method, path string, status int, duration time.Duration) {
	u.program.Send(requestMsg{Method: method, Path: path, Status: status, Duration: duration})
}

func (u *UI) LogWriter() *logWriter {
	return u.logWriter
}

// -----------------------------------------------------------------------------

type model struct {
	public        string
	local         string
	status        string
	dark          bool
	requests      []requestEntry
	totalRequests int
	logs          []string
	maxLogs       int
	maxRequests   int
	width         int
	height        int
	theme         theme
}

type requestEntry struct {
	Method   string
	Path     string
	Status   int
	Duration time.Duration
}

func newModel(host, local string, dark bool) model {
	return model{
		public:      formatURL(host),
		local:       fallbackLocal(local),
		status:      "CONNECTING",
		dark:        dark,
		maxLogs:     200,
		maxRequests: 40,
		theme:       pickTheme(dark),
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case statusMsg:
		m.status = string(msg)
	case publicMsg:
		m.public = string(msg)
	case localMsg:
		m.local = string(msg)
	case requestMsg:
		entry := requestEntry{Method: msg.Method, Path: msg.Path, Status: msg.Status, Duration: msg.Duration}
		m.requests = append(m.requests, entry)
		m.totalRequests++
		if len(m.requests) > m.maxRequests {
			m.requests = m.requests[len(m.requests)-m.maxRequests:]
		}
	case logLineMsg:
		line := strings.TrimSpace(string(msg))
		if line != "" {
			m.logs = append(m.logs, line)
			if len(m.logs) > m.maxLogs {
				m.logs = m.logs[len(m.logs)-m.maxLogs:]
			}
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) View() string {
	width := m.width
	height := m.height
	if width <= 0 {
		width = 100
	}
	if height <= 0 {
		height = 30
	}
	panelWidth := width - 4
	if panelWidth < 40 {
		panelWidth = 40
	}
	hdr := lipgloss.JoinVertical(lipgloss.Left,
		m.theme.line("Public URL", m.public),
		m.theme.line("Local Addr", m.local),
		m.theme.line("Status", m.status),
		m.theme.line("Requests", m.theme.reqCount(m.totalRequests)),
	)
	headerView := m.theme.panel.Width(panelWidth).Render(hdr)

	available := height - lipgloss.Height(headerView) - 6
	if available < 6 {
		available = 6
	}
	reqHeight := (available * 2) / 3
	if reqHeight < 3 {
		reqHeight = 3
	}
	if reqHeight > available-3 {
		reqHeight = available - 3
	}
	logHeight := available - reqHeight
	if logHeight < 3 {
		logHeight = 3
	}

	reqLines := m.renderRequests(reqHeight, panelWidth)
	requestView := m.theme.logPanel.Width(panelWidth).Height(reqHeight).Render(reqLines)

	logLines := strings.Join(m.logsTail(logHeight), "\n")
	if logLines == "" {
		logLines = "Logs will appear here"
	}
	logView := m.theme.logPanel.Width(panelWidth).Height(logHeight).Render(logLines)

	footer := m.theme.footer.Width(panelWidth).Render("Ctrl+C to stop • Logs update live")
	body := lipgloss.JoinVertical(lipgloss.Left, headerView, requestView, logView, footer)
	return lipgloss.Place(width, height, lipgloss.Left, lipgloss.Top, body,
		lipgloss.WithWhitespaceForeground(m.theme.background),
		lipgloss.WithWhitespaceBackground(m.theme.background))
}

func (m model) renderRequests(limit, panelWidth int) string {
	count := len(m.requests)
	if count == 0 {
		return "Waiting for requests..."
	}
	if limit > count {
		limit = count
	}
	pathWidth := panelWidth - 24
	if pathWidth < 8 {
		pathWidth = 8
	}
	start := count - limit
	lines := make([]string, limit)
	for i := 0; i < limit; i++ {
		entry := m.requests[start+i]
		lines[i] = m.theme.requestLine(entry.Method, entry.Path, entry.Status, entry.Duration, pathWidth)
	}
	return strings.Join(lines, "\n")
}

func (m model) logsTail(limit int) []string {
	if len(m.logs) == 0 {
		return nil
	}
	if limit > len(m.logs) {
		limit = len(m.logs)
	}
	start := len(m.logs) - limit
	return m.logs[start:]
}

// -----------------------------------------------------------------------------

type statusMsg string

type publicMsg string

type localMsg string

type requestMsg struct {
	Method   string
	Path     string
	Status   int
	Duration time.Duration
}

type logLineMsg string

// -----------------------------------------------------------------------------

type logWriter struct {
	prog *tea.Program
}

func (w *logWriter) Write(p []byte) (int, error) {
	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		w.prog.Send(logLineMsg(line))
	}
	return len(p), nil
}

// -----------------------------------------------------------------------------

var (
	panelStyleDark = lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#7D56F4")).
		Padding(1, 2)
)

type theme struct {
	panel      lipgloss.Style
	logPanel   lipgloss.Style
	label      lipgloss.Style
	value      lipgloss.Style
	footer     lipgloss.Style
	background lipgloss.Color
	method     lipgloss.Style
	statusOK   lipgloss.Style
	statusWarn lipgloss.Style
	statusErr  lipgloss.Style
}

func pickTheme(dark bool) theme {
	if dark {
		return theme{
			panel: lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(lipgloss.Color("#7D56F4")).
				Padding(1, 2).
				Foreground(lipgloss.Color("#E2E8F0")),
			logPanel: lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("#475569")).
				Padding(0, 1).
				Foreground(lipgloss.Color("#E2E8F0")),
			label: lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Bold(true),
			value: lipgloss.NewStyle().Foreground(lipgloss.Color("#F8FAFC")).Bold(true),
			footer: lipgloss.NewStyle().
				MarginTop(1).
				Foreground(lipgloss.Color("#94A3B8")),
			background: lipgloss.Color("#0F172A"),
			method:     lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Bold(true),
			statusOK:   lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80")).Bold(true),
			statusWarn: lipgloss.NewStyle().Foreground(lipgloss.Color("#FACC15")).Bold(true),
			statusErr:  lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true),
		}
	}
	return theme{
		panel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C3AED")).
			Padding(1, 2).
			Foreground(lipgloss.Color("#1F2933")),
		logPanel: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#CBD5F5")).
			Padding(0, 1).
			Foreground(lipgloss.Color("#1F2933")),
		label: lipgloss.NewStyle().Foreground(lipgloss.Color("#5B21B6")).Bold(true),
		value: lipgloss.NewStyle().Foreground(lipgloss.Color("#111827")).Bold(true),
		footer: lipgloss.NewStyle().
			MarginTop(1).
			Foreground(lipgloss.Color("#4B5563")),
		background: lipgloss.Color("#F8FAFC"),
		method:     lipgloss.NewStyle().Foreground(lipgloss.Color("#2563EB")).Bold(true),
		statusOK:   lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E")).Bold(true),
		statusWarn: lipgloss.NewStyle().Foreground(lipgloss.Color("#EAB308")).Bold(true),
		statusErr:  lipgloss.NewStyle().Foreground(lipgloss.Color("#DC2626")).Bold(true),
	}
}

func (t theme) line(label, value string) string {
	return lipgloss.JoinHorizontal(lipgloss.Left,
		t.label.Render(label+": "),
		t.value.Render(value),
	)
}

func (t theme) reqCount(n int) string {
	return fmt.Sprintf("%d handled", n)
}

func (t theme) requestLine(method, path string, status int, duration time.Duration, pathWidth int) string {
	statusStyle := t.statusOK
	switch {
	case status >= 500:
		statusStyle = t.statusErr
	case status >= 400:
		statusStyle = t.statusWarn
	}
	if pathWidth < 8 {
		pathWidth = 8
	}
	trimmed := truncatePath(path, pathWidth)
	methodCol := t.method.Render(fmt.Sprintf("%-6s", strings.ToUpper(method)))
	pathCol := t.value.Render(fmt.Sprintf(" %-*s", pathWidth, trimmed))
	statusCol := statusStyle.Render(fmt.Sprintf(" %3d", status))
	durCol := t.value.Render(fmt.Sprintf(" (%dms)", duration.Milliseconds()))
	return lipgloss.JoinHorizontal(lipgloss.Left, methodCol, " ", pathCol, statusCol, durCol)
}

func truncatePath(path string, width int) string {
	if len(path) <= width {
		return path
	}
	if width <= 3 {
		if len(path) > width {
			return path[:width]
		}
		return path
	}
	return path[:width-3] + "..."
}

func formatURL(hostname string) string {
	if hostname == "" {
		return "(pending)"
	}
	if strings.HasPrefix(hostname, "http://") || strings.HasPrefix(hostname, "https://") {
		return hostname
	}
	return "https://" + hostname
}

func fallbackLocal(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return "(not set)"
	}
	return addr
}
