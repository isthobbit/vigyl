package globs

import (
	"regexp"
	"testing"
)

func TestToRegex(t *testing.T) {
	cases := []struct {
		glob  string
		match []string
		skip  []string
	}{
		{
			glob:  "fixtures/**",
			match: []string{"fixtures/a.env", "/repo/fixtures/deep/b.txt", `C:\repo\fixtures\c.txt`},
			skip:  []string{"/repo/myfixtures/a.env", "/repo/src/a.env"},
		},
		{
			glob:  "**/*_test.go",
			match: []string{"a_test.go", "/repo/pkg/x/a_test.go", `C:\repo\pkg\a_test.go`},
			skip:  []string{"/repo/pkg/a.go", "/repo/pkg/a_test.go.bak"},
		},
		{
			glob:  "vendor",
			match: []string{"/repo/vendor", "/repo/vendor/lib/x.go"},
			skip:  []string{"/repo/vendored/x.go"},
		},
		{
			glob:  "config.*.yml",
			match: []string{"/repo/config.prod.yml"},
			skip:  []string{"/repo/configXprodXyml", "/repo/config.yml"},
		},
	}
	for _, c := range cases {
		re := regexp.MustCompile(ToRegex(c.glob))
		for _, p := range c.match {
			if !re.MatchString(p) {
				t.Errorf("%q should match %q (regex %s)", c.glob, p, re)
			}
		}
		for _, p := range c.skip {
			if re.MatchString(p) {
				t.Errorf("%q should not match %q (regex %s)", c.glob, p, re)
			}
		}
	}
}
