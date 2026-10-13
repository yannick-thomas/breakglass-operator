package auth

import (
	"errors"
	"testing"
	"time"
)

func TestStore_SessionLifecycle(t *testing.T) {
	store := NewStore()
	a := NewSession(Identity{Username: "jane"}, "Jane", nil, time.Hour)
	b := NewSession(Identity{Username: "max"}, "Max", nil, time.Hour)

	if err := store.Add(a); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(b); err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || a.ID == b.ID {
		t.Fatalf("expected distinct random session IDs, got %q and %q", a.ID, b.ID)
	}

	got, err := store.Get(a.ID)
	if err != nil || got.Identity.Username != "jane" {
		t.Fatalf("expected jane's session, got %+v, %v", got, err)
	}

	store.Delete(a.ID)
	if _, err := store.Get(a.ID); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expected deleted session to be gone, got %v", err)
	}
	if _, err := store.Get("unknown"); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expected unknown session ID to be rejected, got %v", err)
	}
}

func TestStore_ExpiredSession(t *testing.T) {
	store := NewStore()
	sess := NewSession(Identity{Username: "jane"}, "Jane", nil, time.Hour)
	if err := store.Add(sess); err != nil {
		t.Fatal(err)
	}

	store.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := store.Get(sess.ID); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expected expired session to be rejected, got %v", err)
	}
}

func TestStore_PendingLoginIsSingleUse(t *testing.T) {
	store := NewStore()
	if err := store.AddPending("state-1", PendingLogin{Nonce: "n", PKCEVerifier: "v"}); err != nil {
		t.Fatal(err)
	}

	p, ok := store.TakePending("state-1")
	if !ok || p.Nonce != "n" {
		t.Fatalf("expected pending login, got %+v, %v", p, ok)
	}
	if _, ok := store.TakePending("state-1"); ok {
		t.Error("expected a state value to be redeemable only once")
	}
}

func TestStore_PendingLoginExpires(t *testing.T) {
	store := NewStore()
	if err := store.AddPending("state-1", PendingLogin{}); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Now().Add(pendingLoginTTL + time.Minute) }
	if _, ok := store.TakePending("state-1"); ok {
		t.Error("expected expired pending login to be rejected")
	}
}
