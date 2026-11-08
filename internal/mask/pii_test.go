package mask

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/config"
)

func allDetectors() *PIIDetector {
	return NewPIIDetector(config.PIIDetection{Enabled: true})
}

func TestPIIDetect(t *testing.T) {
	d := allDetectors()
	tests := []struct {
		name string
		in   any
		want string // "" = no match
	}{
		// e-mail
		{"email", "taro@example.com", config.PIIEmail},
		{"email in text", "連絡先は taro.yamada+dbgw@mail.example.co.jp です", config.PIIEmail},
		{"email in japanese text no spaces", "メールtaro@example.jpまで", config.PIIEmail},
		{"email carrier style", "taro..x.@docomo.ne.jp", config.PIIEmail},
		{"email uppercase", "TARO@EXAMPLE.COM", config.PIIEmail},
		{"no email: no tld", "root@localhost", ""},
		{"no email: numeric tld", "user@10.0.0.1", ""},
		{"no email: no local", "@example.com", ""},
		{"no email: handle", "follow @dbgateway on social", ""},
		{"no email: at in sql", "SELECT 1 @ 2", ""},
		{"no email: label with hyphen", "a@-example.com", ""},

		// phone_jp
		{"mobile hyphen", "090-1234-5678", config.PIIPhoneJP},
		{"mobile plain", "09012345678", config.PIIPhoneJP},
		{"mobile spaces", "080 1234 5678", config.PIIPhoneJP},
		{"mobile spaced hyphen", "070 - 1234 - 5678", config.PIIPhoneJP},
		{"ip phone", "050-1234-5678", config.PIIPhoneJP},
		{"landline tokyo", "03-1234-5678", config.PIIPhoneJP},
		{"landline plain", "0312345678", config.PIIPhoneJP},
		{"landline parens", "(03)1234-5678", config.PIIPhoneJP},
		{"landline 4-2-4", "0123-45-6789", config.PIIPhoneJP},
		{"toll free 0120", "0120-123-456", config.PIIPhoneJP},
		{"toll free 0800", "0800-123-4567", config.PIIPhoneJP},
		{"full width", "０９０－１２３４－５６７８", config.PIIPhoneJP},
		{"katakana long vowel as hyphen", "090ー1234ー5678", config.PIIPhoneJP},
		{"+81 mobile", "+81 90-1234-5678", config.PIIPhoneJP},
		{"+81 hyphen", "+81-90-1234-5678", config.PIIPhoneJP},
		{"+81 plain", "+819012345678", config.PIIPhoneJP},
		{"+81 landline", "+81 3 1234 5678", config.PIIPhoneJP},
		{"+81 with leading 0", "+81 090-1234-5678", config.PIIPhoneJP},
		{"phone in text", "電話番号は090-1234-5678です", config.PIIPhoneJP},
		{"phone after label", "TEL:03-1234-5678", config.PIIPhoneJP},
		{"no phone: 10-digit mobile prefix", "0901234567", ""},
		{"no phone: 11-digit landline", "03123456789", ""},
		{"no phone: 00 prefix", "0012345678", ""},
		{"no phone: no leading 0", "9012345678", ""},
		{"no phone: glued to letters", "ID09012345678", ""},
		{"no phone: glued suffix", "09012345678abc", ""},
		{"no phone: date time", "2024-01-15 12:30:45", ""},
		{"no phone: odd grouping", "09-0-1-2-3-4-5-6-7-8", ""},
		{"no phone: decimal", "3.0312345678", ""},
		{"no phone: +1", "+1 090 1234", ""},
		{"no phone: postal code", "〒100-0001 東京都", ""},

		// credit_card
		{"visa plain", "4111111111111111", config.PIICreditCard},
		{"visa spaces", "4111 1111 1111 1111", config.PIICreditCard},
		{"visa hyphens", "4111-1111-1111-1111", config.PIICreditCard},
		{"card in text", "my card is 4111 1111 1111 1111 thanks", config.PIICreditCard},
		{"card japanese text", "カード番号：4242424242424242 です", config.PIICreditCard},
		{"mastercard", "5555 5555 5555 4444", config.PIICreditCard},
		{"amex 4-6-5", "3782 822463 10005", config.PIICreditCard},
		{"jcb", "3530111333300000", config.PIICreditCard},
		{"discover", "6011-1111-1111-1117", config.PIICreditCard},
		{"card int64", int64(4111111111111111), config.PIICreditCard},
		{"card json number", json.Number("4111111111111111"), config.PIICreditCard},
		{"no card: luhn fails", "4111111111111112", ""},
		{"no card: luhn fails grouped", "4111 1111 1111 1112", ""},
		{"no card: 16-digit order id failing luhn", "2024110800012345", ""},
		{"no card: bad grouping", "41 11111111 111111", ""},
		{"no card: leading 0", "0000000000000000", ""},
		{"no card: leading 9", "9111111111111111", ""},
		{"no card: inside longer number", "14111111111111111", ""},
		{"no card: glued", "x4111111111111111", ""},
		{"no card: 20 digits", "41111111111111111111", ""},
		{"no card: decimal part", "0.4111111111111111", ""},
		{"no card: uuid", "550e8400-e29b-41d4-a716-446655440000", ""},
		{"no card: luhn-failing int64", int64(4111111111111112), ""},
		{"no card: inside 4-digit chain", "4111 1111 1111 1111 1111", ""},
		{"card followed by cvv", "4111 1111 1111 1111 123", config.PIICreditCard},
		{"no my number: suffix of card-shaped id", "1111 1234 5678 9018", ""},

		// my_number
		{"my number", "123456789018", config.PIIMyNumber},
		{"my number 4-4-4", "1234 5678 9018", config.PIIMyNumber},
		{"my number hyphens", "1234-5678-9018", config.PIIMyNumber},
		{"my number second", "987654321093", config.PIIMyNumber},
		{"my number in text", "個人番号123456789018を登録", config.PIIMyNumber},
		{"my number int64", int64(123456789018), config.PIIMyNumber},
		{"no my number: wrong check digit (order no)", "123456789012", ""},
		{"no my number: order number text", "注文番号 123456789012", ""},
		{"no my number: all zero", "000000000000", ""},
		{"no my number: 3-4-5 grouping", "123 4567 89018", ""},
		{"no my number: float", float64(123456789018.5), ""},
		{"no my number: uuid tail", "550e8400-e29b-41d4-a716-123456789018", ""},
		{"no my number: prefixed id", "ORD-123456789018", ""},
		{"no my number: suffixed id", "123456789018-A", ""},

		// other values
		{"nil", nil, ""},
		{"bool", true, ""},
		{"plain text", "こんにちは、世界", ""},
		{"small int", int64(42), ""},
		{"float id", float64(123456789012), ""},
		{"array element", []any{"a", int64(1), "taro@example.com"}, config.PIIEmail},
		{"map value", map[string]any{"note": "card 4111111111111111"}, config.PIICreditCard},
		{"map key", map[string]any{"taro@example.com": true}, config.PIIEmail},
		{"nested", map[string]any{"a": []any{map[string]any{"tel": "090-1234-5678"}}}, config.PIIPhoneJP},
		{"string slice", []string{"x", "03-1234-5678"}, config.PIIPhoneJP},
		{"bytes", []byte("taro@example.com"), config.PIIEmail},
		{"clean array", []any{"order", int64(123456789012)}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, ok := d.Detect(tt.in)
			if ok != (tt.want != "") || kind != tt.want {
				t.Fatalf("Detect(%#v) = %q, %v; want %q", tt.in, kind, ok, tt.want)
			}
		})
	}
}

func TestPIIRedact(t *testing.T) {
	d := allDetectors()
	tests := []struct{ in, want string }{
		{"taro@example.com", "****"},
		{"my card is 4111 1111 1111 1111 thanks", "my card is **** thanks"},
		{"電話: 090-1234-5678、メール: taro@example.com。", "電話: ****、メール: ****。"},
		{"+81 90-1234-5678", "****"},
		{"(03)1234-5678", "(****"},
		{"cards 4111111111111111 5555555555554444", "cards **** ****"},
		{"tel 0312345678 card 4111111111111111", "tel **** card ****"},
		{"0312345678 4111111111111111", "**** ****"},
		{"order 123456789012 / mn 123456789018", "order 123456789012 / mn ****"},
		{"09012345678@example.com", "****"},
		{"nothing here 12345", "nothing here 12345"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := d.Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPIIDetectorsSelection(t *testing.T) {
	d := NewPIIDetector(config.PIIDetection{Enabled: true, Detectors: []string{config.PIICreditCard}})
	if _, ok := d.Detect("taro@example.com"); ok {
		t.Error("email detected although only credit_card is enabled")
	}
	if _, ok := d.Detect("090-1234-5678"); ok {
		t.Error("phone detected although only credit_card is enabled")
	}
	if k, ok := d.Detect("4111111111111111"); !ok || k != config.PIICreditCard {
		t.Errorf("card: %q %v", k, ok)
	}

	off := NewPIIDetector(config.PIIDetection{Enabled: false})
	if off.Enabled() {
		t.Error("disabled detector reports enabled")
	}
	if _, ok := off.Detect("taro@example.com"); ok {
		t.Error("disabled detector detected")
	}
	if got := off.Redact("taro@example.com"); got != "taro@example.com" {
		t.Errorf("disabled Redact = %q", got)
	}
	var nilD *PIIDetector
	if nilD.Enabled() || nilD.Apply([]any{"taro@example.com"}, []int{0}) != nil {
		t.Error("nil detector must be disabled")
	}
	if nilD.Action() != config.PIIActionMask {
		t.Error("nil detector action")
	}
}

func TestPIIApplyMask(t *testing.T) {
	d := allDetectors()
	nested := []any{"keep", "taro@example.com"}
	row := []any{"taro@example.com", "hello", int64(4111111111111111), nested, nil, "090-1234-5678"}
	found := d.Apply(row, []int{0, 1, 2, 3, 4, 99, -1}) // column 5 is not checked
	want := []PIIFinding{{0, config.PIIEmail}, {2, config.PIICreditCard}, {3, config.PIIEmail}}
	if len(found) != len(want) {
		t.Fatalf("findings = %v, want %v", found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Fatalf("findings = %v, want %v", found, want)
		}
	}
	if row[0] != Redacted || row[1] != "hello" || row[2] != Redacted || row[5] != "090-1234-5678" {
		t.Fatalf("row = %#v", row)
	}
	if got := row[3].([]any); got[0] != "keep" || got[1] != Redacted {
		t.Fatalf("nested = %#v", got)
	}
	if nested[1] != "taro@example.com" {
		t.Fatal("Apply modified the original nested slice")
	}
}

func TestPIIApplyDeny(t *testing.T) {
	d := NewPIIDetector(config.PIIDetection{Enabled: true, Action: config.PIIActionDeny})
	if d.Action() != config.PIIActionDeny {
		t.Fatal("action")
	}
	row := []any{"ok", "card 4111111111111111"}
	found := d.Apply(row, []int{0, 1})
	if len(found) != 1 || found[0].Column != 1 || found[0].Kind != config.PIICreditCard {
		t.Fatalf("findings = %v", found)
	}
	if row[1] != "card 4111111111111111" {
		t.Fatal("deny must not modify the row")
	}
}

func TestPIIRedactValue(t *testing.T) {
	d := allDetectors()
	in := map[string]any{"name": "taro", "contact": map[string]any{"mail": "x taro@example.com"}}
	out, ok := d.RedactValue(in)
	if !ok {
		t.Fatal("not found")
	}
	got := out.(map[string]any)["contact"].(map[string]any)["mail"]
	if got != "x ****" {
		t.Fatalf("got %v", got)
	}
	if in["contact"].(map[string]any)["mail"] != "x taro@example.com" {
		t.Fatal("input modified")
	}
	if v, ok := d.RedactValue(map[string]any{"taro@example.com": 1}); !ok || v != Redacted {
		t.Fatalf("key: %v %v", v, ok)
	}
	if v, ok := d.RedactValue("clean"); ok || v != "clean" {
		t.Fatalf("clean: %v %v", v, ok)
	}
}

func TestPIIBounds(t *testing.T) {
	d := allDetectors()
	// Beyond the scan window: not detected (documented trade-off).
	late := strings.Repeat("a", maxPIIScanBytes) + " taro@example.com"
	if _, ok := d.Detect(late); ok {
		t.Error("match beyond the scan window was reported")
	}
	if got := d.Redact(late); got != late {
		t.Error("Redact changed text beyond the scan window")
	}
	early := "taro@example.com " + strings.Repeat("a", 1<<20)
	if _, ok := d.Detect(early); !ok {
		t.Error("match at the start of a long string missed")
	}
	// Deep nesting stops at maxPIIDepth.
	var v any = "taro@example.com"
	for range maxPIIDepth + 2 {
		v = []any{v}
	}
	if _, ok := d.Detect(v); ok {
		t.Error("match beyond the depth limit was reported")
	}
	// Many elements stop at maxPIIElements.
	many := make([]any, maxPIIElements+10)
	for i := range many {
		many[i] = "x"
	}
	many[len(many)-1] = "taro@example.com"
	if _, ok := d.Detect(many); ok {
		t.Error("match beyond the element limit was reported")
	}
}

// TestMyNumberCheckDigit verifies that exactly one check digit is valid for
// any 11-digit base, and that it rejects the others.
func TestMyNumberCheckDigit(t *testing.T) {
	for _, base := range []string{"12345678901", "98765432109", "20231108000", "31415926535", "00000000001"} {
		valid := 0
		for c := '0'; c <= '9'; c++ {
			if validMyNumber([]byte(base + string(c))) {
				valid++
			}
		}
		if valid != 1 {
			t.Errorf("%s: %d valid check digits", base, valid)
		}
	}
}

func FuzzPIIDetector(f *testing.F) {
	for _, s := range []string{
		"", "taro@example.com", "+81 90-1234-5678", "4111 1111 1111 1111", "1234-5678-9018",
		"＋８１（０３）１２３４－５６７８", "@@@..@@", "+", "+8", "0.4111111111111111.", "\xff\xfe090-1234-5678",
		strings.Repeat("1 ", 3000), strings.Repeat("a@b.", 2000),
	} {
		f.Add(s)
	}
	d := allDetectors()
	deny := NewPIIDetector(config.PIIDetection{Enabled: true, Action: config.PIIActionDeny})
	f.Fuzz(func(t *testing.T, s string) {
		kind, ok := d.Detect(s)
		red := d.Redact(s)
		if ok != (red != s) {
			t.Fatalf("Detect=%v but Redact changed=%v for %q", ok, red != s, s)
		}
		if ok && kind == "" {
			t.Fatal("empty kind")
		}
		if ok {
			// A redacted string must not still contain a match in the
			// scanned window that Redact covered.
			if len(s) <= maxPIIScanBytes/2 {
				if k, again := d.Detect(red); again {
					t.Fatalf("redacted %q still contains %s: %q", s, k, red)
				}
			}
		}
		row := []any{s, []any{s}, map[string]any{"k": s}}
		d.Apply(row, []int{0, 1, 2})
		deny.Apply([]any{s}, []int{0})
	})
}

func BenchmarkPIIDetect(b *testing.B) {
	d := allDetectors()
	inputs := map[string]string{
		"short":      "山田太郎",
		"text":       strings.Repeat("ご注文ありがとうございました。注文番号 123456789012 ", 20),
		"worst-sep":  strings.Repeat("1 ", 4096),
		"worst-at":   strings.Repeat("a@", 4096),
		"long-clean": strings.Repeat("abcdefgh", 1<<14),
	}
	for name, in := range inputs {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				d.Detect(in)
			}
		})
	}
}
