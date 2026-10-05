package osv_test

import (
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/deps/osv"
)

// report mirrors real osv-scanner v2 output: OSV IDs (PYSEC/GHSA) with the
// CVE in aliases, a CVSS vector in severity, and the numeric score only in
// the group's max_severity.
var report = []byte(`{"results":[{"source":{"path":"/repo/requirements.txt","type":"lockfile"},
"packages":[{"package":{"name":"requests","version":"2.19.0","ecosystem":"PyPI"},
 "vulnerabilities":[
  {"id":"PYSEC-2018-28","aliases":["CVE-2018-18074","GHSA-x84v-xcm2-53pg"],
   "summary":"auth header leak","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
   "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.20.0"}]}]}]},
  {"id":"GHSA-9wx4-h78v-vm56","aliases":[],
   "summary":"no CVE yet","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}]},
  {"id":"GHSA-crit-0000-0000","aliases":["CVE-2099-0001"],"summary":"critical, scored in severity",
   "severity":[{"type":"CVSS_V3","score":"9.8"}]}
 ],
 "groups":[
  {"ids":["PYSEC-2018-28","GHSA-x84v-xcm2-53pg"],"aliases":["CVE-2018-18074","GHSA-x84v-xcm2-53pg","PYSEC-2018-28"],"max_severity":"7.5"},
  {"ids":["GHSA-9wx4-h78v-vm56"],"aliases":["GHSA-9wx4-h78v-vm56"],"max_severity":""},
  {"ids":["GHSA-crit-0000-0000"],"aliases":["CVE-2099-0001"],"max_severity":""}
 ]}]}]}`)

func TestParseOutput_AliasesAndSeverity(t *testing.T) {
	findings, err := osv.ParseOutputForTest(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	want := []struct{ id, severity string }{
		// CVE taken from aliases; HIGH from the group's 7.5, not LOW from the vector.
		{"CVE-2018-18074", "HIGH"},
		// No CVE anywhere: keep the OSV ID, never borrow another group's CVE.
		// The vector cannot be scored and there is no group score: MEDIUM, not LOW.
		{"GHSA-9wx4-h78v-vm56", "MEDIUM"},
		// A plain numeric score in severity is used when the group has none.
		{"CVE-2099-0001", "CRITICAL"},
	}
	for i, w := range want {
		if findings[i].CVEID != w.id || findings[i].Severity != w.severity {
			t.Errorf("finding %d = %s %s, want %s %s", i, findings[i].CVEID, findings[i].Severity, w.id, w.severity)
		}
	}
	if findings[0].FixedVersion != "2.20.0" {
		t.Errorf("fixed version = %q", findings[0].FixedVersion)
	}
}
