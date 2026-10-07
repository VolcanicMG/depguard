package pyver

import "testing"

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.9", "1.10", -1}, {"1.0", "1.0.0", 0}, {"1.0.0", "1.0", 0}, {"2", "1.99", 1},
		{"2", "10", -1}, {"1.0", "1.0.1", -1}, {"0.9.9", "1", -1}, {"3.0", "3.0", 0},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s) = %d, want %d", c.a, c.b, got, c.want)
		}
		if Less(c.a, c.b) != (c.want < 0) {
			t.Errorf("Less(%s,%s) disagrees with Compare", c.a, c.b)
		}
	}
}

func TestStable(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "2": true, "1.0rc1": false, "1.0.post1": false, "1.0.dev0": false,
		"1..0": false, "1.0+local": false, "1!2.0": false, "": false, "1.0a1": false,
	} {
		if Stable(v) != want {
			t.Errorf("Stable(%q) != %v", v, want)
		}
	}
}

func TestFileVersion(t *testing.T) {
	cases := map[string]string{
		"requests-2.31.0-py3-none-any.whl":                  "2.31.0",
		"numpy-1.26.4-1-cp312-cp312-manylinux_2_17_x86.whl": "1.26.4", // build tag
		"torch-2.1.0+cpu-cp311-cp311-linux_x86_64.whl":      "2.1.0+cpu",
		"my_pkg-1.0.post1.tar.gz":                           "1.0.post1",
		"my-dashed-pkg-0.3.zip":                             "0.3",
		"Pkg-1.0RC1.tar.bz2":                                "1.0rc1",
	}
	for fn, want := range cases {
		if got, ok := FileVersion(fn); !ok || got != want {
			t.Errorf("FileVersion(%q) = %q,%v want %q", fn, got, ok, want)
		}
	}
	for _, bad := range []string{"pkg.egg", "pkg-1.0.exe", "pkg.tar.gz", "pkg-.zip", "a-b-c.whl", "x-1.0.tar.xz", ""} {
		if _, ok := FileVersion(bad); ok {
			t.Errorf("FileVersion(%q) parsed, want fail", bad)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{"Foo_Bar.baz": "foo-bar-baz", "A--B": "a-b", "requests": "requests"} {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
