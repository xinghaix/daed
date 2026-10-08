package netproxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const markerMethod = "WriteDeadlineClosesSession"

// delegatingWrapperPackages are packages that wrap a conn in a struct which
// embeds netproxy.Conn / net.Conn / netproxy.PacketConn. Every concrete type in
// them that declares SetWriteDeadline must also make the optional
// WriteDeadlineBehavior declaration reachable, either by declaring it or by
// embedding a struct that does. Interface embedding promotes SetWriteDeadline
// but not unknown optional methods, so without that the wrapped conn's
// destructive-deadline declaration is silently erased.
var delegatingWrapperPackages = []string{
	"netproxy",
	"protocol/http",
	"protocol/shadowsocks",
	"protocol/shadowsocks_2022",
	"protocol/shadowsocks_stream",
	"protocol/socks5",
	"protocol/trojanc",
	"protocol/vmess",
	"transport/httpheader",
	"transport/httpupgrade",
	"transport/mux",
	"transport/shadowsocksr/obfs",
	"transport/shadowsocksr/proto",
	"transport/simpleobfs",
}

// deadlineBearingConnTypes are the embedded conn types that actually carry a
// deadline method. A wrapper embedding one of these exposes SetWriteDeadline by
// promotion; a wrapper embedding any other interface does not, which is why the
// check below is keyed on this set and not on "the field name contains Conn".
var deadlineBearingConnTypes = map[string]bool{
	"Conn":                 true, // netproxy.Conn
	"PacketConn":           true, // netproxy.PacketConn
	"FakeNetConn":          true, // netproxy.FakeNetConn
	"fakeNetPacketConn":    true,
	"fakeNetPacketConn2":   true,
	"quicStreamPacketConn": true,
	"TLSObfs":              true,
	"HTTPObfs":             true,
	"bufferedConn":         true,
	"udpHopPacketConn":     true,
	"udpConn":              true,
	"obfsPacketConn":       true,
	"TransportPacketConn":  true,
	"PktConn":              true,
	"UdpConn":              true,
	"demojiConn":           true,
}

// packageDecls is the method/type inventory of one package's non-test files.
type packageDecls struct {
	// methods holds "Type.Method" for every top-level func with a receiver.
	methods map[string]bool
	// types is every type name declared in the package.
	types map[string]bool
	// embedsDeadlineConn holds type names that embed a conn interface known to
	// carry SetWriteDeadline (deadlineBearingConnTypes). Such a type promotes
	// that method but NOT the optional marker.
	embedsDeadlineConn map[string]bool
	// embeddedTypes holds, per type, the type names of its embedded fields.
	embeddedTypes map[string][]string
}

// declaresMarkerFor reports whether WriteDeadlineClosesSession is reachable on
// typeName: declared on the type itself, or promoted from an embedded struct
// type. It deliberately does NOT accept "some other type in this package
// declares it", which is what made an earlier version of this guard blind to a
// single wrapper losing its forward.
func (p *packageDecls) declaresMarkerFor(typeName string) bool {
	if p.methods[typeName+"."+markerMethod] {
		return true
	}
	for _, embedded := range p.embeddedTypes[typeName] {
		if p.methods[embedded+"."+markerMethod] {
			return true
		}
	}
	return false
}

// collectPackageDecls parses the package's non-test Go files.
func collectPackageDecls(t *testing.T, dir string) *packageDecls {
	t.Helper()
	decls := &packageDecls{
		methods:            make(map[string]bool),
		types:              make(map[string]bool),
		embedsDeadlineConn: make(map[string]bool),
		embeddedTypes:      make(map[string][]string),
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					decls.types[ts.Name.Name] = true
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						if len(field.Names) != 0 {
							continue // named field, not an embedded one
						}
						name := embeddedTypeName(field.Type)
						if name == "" {
							continue
						}
						decls.embeddedTypes[ts.Name.Name] = append(decls.embeddedTypes[ts.Name.Name], name)
						if deadlineBearingConnTypes[name] {
							decls.embedsDeadlineConn[ts.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					continue
				}
				recv := d.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				ident, ok := recv.(*ast.Ident)
				if !ok {
					continue
				}
				decls.methods[ident.Name+"."+d.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	return decls
}

// embeddedTypeName returns the bare type name of an embedded field.
func embeddedTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return embeddedTypeName(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// moduleRoot walks up from the test's working directory to the module root.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// TestWriteDeadlineMarkerCoversDelegatingWrappers is the P3-32 guard, and the
// publish precondition for this cluster: a wrapper that loses the declaration
// makes deadline-arming callers (dae's UdpEndpoint) arm a session-closing timer
// they believe is an ordinary write deadline. A wrapper with a plain delegate
// SetWriteDeadline is harmless; the reachable method is what it inherits from
// its embedded conn.
//
// The check is structural rather than reflective so it also covers types whose
// constructors need a live connection.
func TestWriteDeadlineMarkerCoversDelegatingWrappers(t *testing.T) {
	root := moduleRoot(t)
	checked := 0
	for _, dir := range delegatingWrapperPackages {
		pkgDir := filepath.Join(root, dir)
		decls := collectPackageDecls(t, pkgDir)

		var candidates []string
		for name := range decls.types {
			if decls.methods[name+".SetWriteDeadline"] || decls.embedsDeadlineConn[name] {
				candidates = append(candidates, name)
			}
		}
		sort.Strings(candidates)

		for _, name := range candidates {
			checked++
			if decls.declaresMarkerFor(name) {
				continue
			}
			t.Errorf("%s: type %s exposes SetWriteDeadline (declared, or promoted from an "+
				"embedded conn) but neither it nor an embedded struct declares %s, so the "+
				"wrapped conn's destructive-deadline declaration is erased here",
				dir, name, markerMethod)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d conn-shaped types inspected; the scanner is not seeing the wrapper "+
			"types it is supposed to guard", checked)
	}
}

// TestWriteDeadlineMarkerGuardSeesKnownTypes pins that the scanner still finds
// the types this guard exists for: a rename or a move would otherwise turn the
// guard into a silent no-op.
func TestWriteDeadlineMarkerGuardSeesKnownTypes(t *testing.T) {
	root := moduleRoot(t)
	decls := collectPackageDecls(t, filepath.Join(root, "transport/simpleobfs"))
	for _, name := range []string{"TLSObfs", "HTTPObfs"} {
		if !decls.types[name] {
			t.Fatalf("transport/simpleobfs: type %s not found; the guard is scanning the wrong thing", name)
		}
		if !decls.declaresMarkerFor(name) {
			t.Fatalf("transport/simpleobfs: %s.%s not detected", name, markerMethod)
		}
		if !decls.embedsDeadlineConn[name] {
			t.Fatalf("transport/simpleobfs: %s is not seen as embedding a deadline-bearing conn", name)
		}
	}
}

// TestWriteDeadlineMarkerGuardDetectsErasure is the negative control: an
// embedded-interface wrapper WITHOUT the forward must be reported. The synthetic
// package is parsed from source, so it exercises the same code path the guard
// uses on the real packages.
func TestWriteDeadlineMarkerGuardDetectsErasure(t *testing.T) {
	dir := t.TempDir()
	src := `package synthetic

import (
	"net"
	"time"
)

type erasedConn struct {
	net.Conn
}

func (c *erasedConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
`
	if err := os.WriteFile(filepath.Join(dir, "conn.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write synthetic package: %v", err)
	}
	decls := collectPackageDecls(t, dir)
	if !decls.methods["erasedConn.SetWriteDeadline"] {
		t.Fatal("scanner missed the synthetic SetWriteDeadline definer")
	}
	if !decls.embedsDeadlineConn["erasedConn"] {
		t.Fatal("scanner missed the embedded deadline-bearing conn")
	}
	if decls.declaresMarkerFor("erasedConn") {
		t.Fatal("scanner reported a marker the synthetic package does not declare")
	}
}
