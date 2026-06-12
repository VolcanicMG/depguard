package trace

import "testing"

// TestIsSecretPath locks in the path-BOUNDARY matching: real credential
// locations are flagged, look-alike names are not, and the box's own mounts are
// exempt. Plain strings.Contains used to false-positive on the negative cases.
func TestIsSecretPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Real credential locations on a host → flagged.
		{"/root/.ssh/id_rsa", true},
		{"/root/.ssh", true},
		{"/home/user/.aws/credentials", true},
		{"/etc/shadow", true},
		{"/root/.docker/config.json", true}, // the ".json" suffix must still match
		{"/root/.npmrc", true},
		{"/root/.npmrc.bak", true}, // a backup still holds the token
		{"/root/id_ed25519", true},
		// Boundary false-positives the old substring match tripped on → NOT flagged.
		{"/usr/lib/id_rsa_helper", false}, // "id_rsa" is part of a longer name
		{"/root/.ssh-config", false},      // ".ssh" is part of a longer name
		{"/var/cache/sshd", false},        // no fragment at all
		// The box's own mounts are exempt: reading them proves nothing.
		{"/app/node_modules/foo/index.js", false},
		{"/app/build/id_rsa_helper.js", false},
		{"/home/node/.npmrc", false},
		{"/tmp/scratch/id_rsa", false},
	}
	for _, c := range cases {
		if got := isSecretPath(c.path); got != c.want {
			t.Errorf("isSecretPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestHasPathFragment exercises the boundary helper directly.
func TestHasPathFragment(t *testing.T) {
	cases := []struct {
		path, frag string
		want       bool
	}{
		{"/root/.ssh/id_rsa", "/.ssh", true},
		{"/root/.ssh/id_rsa", "id_rsa", true},
		{"/x/.docker/config.json", "/.docker/config", true},
		{"/x/id_rsa_helper", "id_rsa", false},
		{"/x/.ssh-config", "/.ssh", false},
		{"/x/foo", "id_rsa", false},
		{"anything", "", false},
	}
	for _, c := range cases {
		if got := hasPathFragment(c.path, c.frag); got != c.want {
			t.Errorf("hasPathFragment(%q, %q) = %v, want %v", c.path, c.frag, got, c.want)
		}
	}
}
