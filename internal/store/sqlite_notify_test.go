package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSlackLinkCodes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()

	if err := s.CreateSlackLinkCode(ctx, "taro@example.com", "h1", now, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A new code replaces the earlier one.
	if err := s.CreateSlackLinkCode(ctx, "taro@example.com", "h2", now, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeSlackLinkCode(ctx, "h1", "U1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replaced code: err = %v", err)
	}
	email, err := s.ConsumeSlackLinkCode(ctx, "h2", "U1", now)
	if err != nil || email != "taro@example.com" {
		t.Fatalf("consume = %q, %v", email, err)
	}
	if _, err := s.ConsumeSlackLinkCode(ctx, "h2", "U1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reused code: err = %v", err)
	}
	l, err := s.GetSlackLinkBySlackUser(ctx, "U1")
	if err != nil || l.Email != "taro@example.com" {
		t.Fatalf("link = %+v, %v", l, err)
	}

	// Expired codes fail and are deleted.
	if err := s.CreateSlackLinkCode(ctx, "hanako@example.com", "h3", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeSlackLinkCode(ctx, "h3", "U2", now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: err = %v", err)
	}
	if _, err := s.ConsumeSlackLinkCode(ctx, "h3", "U2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code was kept: err = %v", err)
	}

	// Linking the same Slack user to another account moves the link.
	if err := s.CreateSlackLinkCode(ctx, "hanako@example.com", "h4", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeSlackLinkCode(ctx, "h4", "U1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSlackLinkByEmail(ctx, "taro@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old link kept: %v", err)
	}
	if email, err := s.DeleteSlackLinkBySlackUser(ctx, "U1"); err != nil || email != "hanako@example.com" {
		t.Fatalf("unlink = %q, %v", email, err)
	}
	if _, err := s.DeleteSlackLinkBySlackUser(ctx, "U1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlink twice: %v", err)
	}
	if err := s.DeleteSlackLink(ctx, "nobody@example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestSlackThreadsAndNotifyState(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	for _, th := range []*SlackThread{
		{RequestID: "req_1", Channel: "C1", Target: "#a", TS: "1.1", EventJSON: []byte(`{}`), CreatedAt: now},
		{RequestID: "req_1", Channel: "C2", Target: "#b", TS: "2.2", EventJSON: []byte(`{}`), CreatedAt: now.Add(time.Second)},
		{RequestID: "req_1", Channel: "C1", Target: "#a", TS: "1.5", EventJSON: []byte(`{"x":1}`), CreatedAt: now},
	} {
		if err := s.SaveSlackThread(ctx, th); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListSlackThreads(ctx, "req_1")
	if err != nil || len(got) != 2 || got[0].TS != "1.5" || string(got[0].EventJSON) != `{"x":1}` || got[1].Channel != "C2" {
		t.Fatalf("threads = %+v, %v", got, err)
	}

	prev, found, err := s.SwapNotifyState(ctx, "k", "v1", now)
	if err != nil || found || prev != "" {
		t.Fatalf("first swap = %q %v %v", prev, found, err)
	}
	prev, found, err = s.SwapNotifyState(ctx, "k", "v2", now)
	if err != nil || !found || prev != "v1" {
		t.Fatalf("second swap = %q %v %v", prev, found, err)
	}
}
