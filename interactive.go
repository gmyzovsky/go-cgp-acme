package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Let's Encrypt endpoints used by the fileless convenience path
// (standaloneConfig). They are deliberately not a default for an empty
// directory_url in a configuration file - a file must name its CA
// explicitly - but a one-off run with no file at all targets Let's
// Encrypt, its production endpoint by default and staging under
// --staging. Any other CA (or EAB) requires a configuration file.
const (
	letsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// flagPassed reports whether the named flag was set on the command
// line, as opposed to left at its default.
func flagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// defaultConfigPaths lists the configuration files to try, in priority
// order, when -config is not given: first one next to the executable (a
// portable copy travels with its config - copy the binary and run it),
// then the system path (a deb/rpm package installs it in /etc).
func defaultConfigPaths() []string {
	paths := make([]string, 0, 2)
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		paths = append(paths, filepath.Join(filepath.Dir(exe), configBaseName))
	}
	return append(paths, defaultConfigPath)
}

// firstExisting returns the first path that exists, or "" if none do.
func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// standaloneConfig builds a fileless configuration for a one-off run
// when no configuration file is present: the same defaults LoadConfig
// applies, wired to Let's Encrypt (production, or staging under
// --staging). The CGP connection is left to be supplied by a connection
// string or filled in interactively.
func standaloneConfig() *Config {
	return &Config{
		CGP: CGPConfig{Host: "localhost"},
		ACME: ACMEConfig{
			DirectoryURL:  letsEncryptProduction,
			StagingURL:    letsEncryptStaging,
			KeyBits:       2048,
			RenewFraction: 1.0 / 3.0,
		},
		Storage: StorageConfig{Path: "private/acme"},
	}
}

// parseConnString parses a "[login[:password]@]host[:port]" connection
// string into a CGPConfig. An omitted port is left at zero, which
// CGPConfig.Addr resolves from the transport; a password may contain
// ':' (only the first separates it from the login). A missing login or
// password is left empty for the caller to fill interactively; the host
// is required. An IPv6 literal is written bracketed, as everywhere else
// a host and a port share a string.
func parseConnString(s string) (CGPConfig, error) {
	var cfg CGPConfig
	hostport := s
	if at := strings.LastIndex(s, "@"); at >= 0 {
		userinfo := s[:at]
		hostport = s[at+1:]
		if colon := strings.IndexByte(userinfo, ':'); colon >= 0 {
			cfg.Login = userinfo[:colon]
			cfg.Password = userinfo[colon+1:]
		} else {
			cfg.Login = userinfo
		}
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return CGPConfig{}, err
	}
	cfg.Host, cfg.Port = host, port
	if cfg.Host == "" {
		return CGPConfig{}, fmt.Errorf("missing host in connection string %q", s)
	}
	return cfg, nil
}

// splitHostPort splits the host part of a connection string, with a
// zero port when none was given. net.SplitHostPort is no help here: it
// insists on a port. The three shapes are a bracketed IPv6 literal
// (with or without a port), a bare IPv6 literal - which has colons of
// its own and therefore no port - and a name or IPv4 address.
func splitHostPort(s string) (host string, port int, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("unterminated IPv6 address in connection string %q", s)
		}
		host = s[1:end]
		switch rest := s[end+1:]; {
		case rest == "":
			return host, 0, nil
		case strings.HasPrefix(rest, ":"):
			port, err = parsePort(rest[1:])
			return host, port, err
		default:
			return "", 0, fmt.Errorf("unexpected %q after the IPv6 address in a connection string", rest)
		}
	}
	if strings.Count(s, ":") > 1 {
		return s, 0, nil // a bare IPv6 literal
	}
	if colon := strings.LastIndex(s, ":"); colon >= 0 {
		port, err = parsePort(s[colon+1:])
		return s[:colon], port, err
	}
	return s, 0, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q in connection string", s)
	}
	return port, nil
}

// collectCGP fills the CGP connection fields from the terminal. With
// full set it prompts for every field (a pure interactive run with no
// configuration file and no connection string); otherwise it prompts
// only for fields still empty, completing a connection string that
// omitted, typically, the password. It fails if a prompt is needed but
// stdin is not a terminal.
func collectCGP(cgp *CGPConfig, full bool) error {
	if full || cgp.Host == "" || cgp.Login == "" || cgp.Password == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("interactive input required but stdin is not a terminal; provide -config or a full login:password@host:port")
		}
	}

	in := bufio.NewReader(os.Stdin)
	if full || cgp.Host == "" {
		v, err := promptLine(in, "CGP host", defaultOr(cgp.Host, "localhost"))
		if err != nil {
			return err
		}
		cgp.Host = v
	}
	if full {
		mode, err := cgp.TLSMode()
		if err != nil {
			return err
		}
		v, err := promptLine(in, "CGP port", strconv.Itoa(cgp.portFor(mode)))
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port %q", v)
		}
		cgp.Port = port
	}
	if full || cgp.Login == "" {
		v, err := promptLine(in, "CGP login", defaultOr(cgp.Login, "postmaster"))
		if err != nil {
			return err
		}
		cgp.Login = v
	}
	if full || cgp.Password == "" {
		v, err := promptSecret("CGP password")
		if err != nil {
			return err
		}
		cgp.Password = v
	}
	cgp.Login = qualifyLogin(cgp.Login, cgp.Host)
	if cgp.Login == "" || cgp.Password == "" {
		return fmt.Errorf("cgp login and password are required")
	}
	return nil
}

// qualifyLogin gives a bare CLI login a domain part. CommuniGate Pro
// accepts an account name without one and derives the domain per access
// protocol - for PWD/CLI, from the IP-to-domain binding of the
// connection - which can authenticate the login in an unintended domain
// and deny it the Server Administrator rights it holds only in its own.
// Appending @<host> pins the login to the domain named by the host we
// connect to, be it an FQDN (a node's main domain is its FQDN) or an IP
// (resolved by the same binding, but explicitly). A login that already
// carries an '@' - or an empty one - is left untouched. Only logins
// taken from a connection string or interactive prompt are qualified; a
// configuration file's login is used verbatim.
func qualifyLogin(login, host string) string {
	if login == "" || strings.Contains(login, "@") {
		return login
	}
	return login + "@" + host
}

// promptLine writes "label [def]: " and reads one line, returning def
// when the reply is empty.
func promptLine(in *bufio.Reader, label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// promptSecret reads a secret from the terminal without echoing it.
func promptSecret(label string) (string, error) {
	fmt.Printf("%s: ", label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func defaultOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
