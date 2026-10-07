package typosquat

import "testing"

// The PyPI list must not flag the real top of PyPI — including names one edit
// from npm's list ("requests" vs "request") — and must flag close squats.
func TestSuspicionPyPI(t *testing.T) {
	for _, ok := range []string{
		"requests", "numpy", "scipy", "scapy", "boto", "boto3", "botocore", "pyaml", "pyyaml",
		"jinja", "jinja2", "six", "attrs", "idna", "charset-normalizer", "packaging",
		"typing-extensions", "pip", "wheel", "click", "markupsafe", "python-dateutil", "pytz",
		"rich", "tqdm", "panda", "pandas", "s3transfer", "urllib3", "setuptools", "numba",
		"torch", "flask", "django", "celery", "vine", "redis", "pytest", "pluggy", "iniconfig",
		"certifi", "cryptography", "cffi", "pycparser", "pydantic", "matplotlib",
	} {
		if reason, bad := SuspicionPyPI(ok); bad {
			t.Errorf("SuspicionPyPI(%q) flagged: %s", ok, reason)
		}
	}
	for _, squat := range []string{"reqeusts", "requestss", "numpyy", "djanga", "pandsa", "urlib3", "rеquests"} {
		if _, bad := SuspicionPyPI(squat); !bad {
			t.Errorf("SuspicionPyPI(%q) not flagged", squat)
		}
	}
	// npm behaviour unchanged: "requests" is still one edit from npm's "request".
	if _, bad := Suspicion("requests"); !bad {
		t.Error("npm Suspicion changed")
	}
}

func TestSuspicionPyPITable(t *testing.T) {
	// PEP 503 turns py_yaml / py.yaml into "py-yaml" (not "pyyaml"), one insert away.
	for _, squat := range []string{"requsts", "reqeusts", "numpi", "pandsa", "djang0", "pyyml", "urllib2", "py-yaml", "rеquests"} {
		if _, bad := SuspicionPyPI(squat); !bad {
			t.Errorf("%q not flagged", squat)
		}
	}
	var clean []string
	for n := range pypiPopular {
		clean = append(clean, n)
	}
	for n := range pypiKnown {
		clean = append(clean, n)
	}
	clean = append(clean, "reqests2", "djangoxx", "numpyyy") // two edits away
	for _, n := range clean {
		if reason, bad := SuspicionPyPI(n); bad {
			t.Errorf("%q flagged: %s", n, reason)
		}
	}
}

func TestSuspicionNpmUnchanged(t *testing.T) {
	for name, want := range map[string]bool{"lodahs": true, "expresss": true, "lodash": false, "react": false, "preact": false, "left-pad": false} {
		if _, bad := Suspicion(name); bad != want {
			t.Errorf("Suspicion(%q) = %v, want %v", name, bad, want)
		}
	}
}
