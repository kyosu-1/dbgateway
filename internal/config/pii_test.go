package config

import (
	"slices"
	"strings"
	"testing"
)

func TestPIIDetectionConfig(t *testing.T) {
	c, err := Parse([]byte("auth: { dev_login: true }\npii_detection: { enabled: true }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.PIIDetection.Action != PIIActionMask || !slices.Equal(c.PIIDetection.Detectors, PIIDetectors) {
		t.Fatalf("defaults = %+v", c.PIIDetection)
	}
	c, err = Parse([]byte("auth: { dev_login: true }\npii_detection: { enabled: true, detectors: [email, my_number], action: deny }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.PIIDetection.Action != PIIActionDeny || !slices.Equal(c.PIIDetection.Detectors, []string{PIIEmail, PIIMyNumber}) {
		t.Fatalf("explicit = %+v", c.PIIDetection)
	}
	for _, tt := range []struct{ yaml, want string }{
		{"pii_detection: { enabled: true, action: block }", "pii_detection.action"},
		{"pii_detection: { enabled: true, detectors: [email, ssn] }", `unknown detector "ssn"`},
		{"pii_detection: { enabled: true, detectors: [email, email] }", `duplicate "email"`},
	} {
		_, err := Parse([]byte("auth: { dev_login: true }\n" + tt.yaml + "\n"))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.yaml, err, tt.want)
		}
	}
}
