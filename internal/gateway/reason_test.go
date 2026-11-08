package gateway

import "testing"

func TestReasonTooVague(t *testing.T) {
	for r, want := range map[string]bool{
		"":              true,
		"fix":           true,
		"checking":      true,
		"Investigation": true,
		"just checking": true,
		"調査":            true,
		"念のため":          true,
		"Support ticket #1234: checking the plan of the affected user": false,
		"問い合わせ#1234の調査のため、該当ユーザーのプランを確認":                               false,
	} {
		if got := reasonTooVague(r); got != want {
			t.Errorf("reasonTooVague(%q) = %v, want %v", r, got, want)
		}
	}
}
