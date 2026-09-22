package service

import (
	"context"
	"testing"
)

// fakeRPMCache 是 RPMCache 的可控测试实现：按账号 ID 返回预置计数。
type fakeRPMCache struct {
	counts map[int64]int
}

func (f *fakeRPMCache) IncrementRPM(_ context.Context, accountID int64) (int, error) {
	f.counts[accountID]++
	return f.counts[accountID], nil
}

func (f *fakeRPMCache) GetRPM(_ context.Context, accountID int64) (int, error) {
	return f.counts[accountID], nil
}

func (f *fakeRPMCache) GetRPMBatch(_ context.Context, ids []int64) (map[int64]int, error) {
	out := make(map[int64]int, len(ids))
	for _, id := range ids {
		out[id] = f.counts[id]
	}
	return out, nil
}

func newOpenAIRPMTestService(t *testing.T, counts map[int64]int) (*OpenAIGatewayService, *fakeRPMCache) {
	t.Helper()
	if counts == nil {
		counts = map[int64]int{}
	}
	cache := &fakeRPMCache{counts: counts}
	return &OpenAIGatewayService{rpmCache: cache}, cache
}

func openAIRPMLimitedOAuthAccount() *Account {
	return &Account{
		ID:         243,
		Platform:   PlatformOpenAI,
		Type:       AccountTypeOAuth,
		Extra:      map[string]any{"base_rpm": 40, "rpm_strategy": "tiered"},
	}
}

func TestOpenAIAccountRPMSchedulable(t *testing.T) {
	account := openAIRPMLimitedOAuthAccount() // base 40, tiered, buffer=floor(40/5)=8

	cases := []struct {
		name    string
		current int
		sticky  bool
		ok      bool
		reason  string
	}{
		{"green zone", 10, false, true, ""},
		{"yellow zone non-sticky", 40, false, false, "rpm_sticky_only"},
		{"yellow zone sticky", 44, true, true, ""},
		{"red zone non-sticky", 48, false, false, "rpm_red"},
		{"red zone sticky", 60, true, false, "rpm_red"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newOpenAIRPMTestService(t, map[int64]int{account.ID: tc.current})
			ok, reason := svc.isOpenAIAccountRPMSchedulable(context.Background(), account, tc.sticky)
			if ok != tc.ok || reason != tc.reason {
				t.Errorf("got (%v, %q), want (%v, %q)", ok, reason, tc.ok, tc.reason)
			}
		})
	}

	t.Run("no rpm cache fails open", func(t *testing.T) {
		svc := &OpenAIGatewayService{}
		if ok, reason := svc.isOpenAIAccountRPMSchedulable(context.Background(), account, false); !ok || reason != "" {
			t.Errorf("nil cache must fail open, got (%v, %q)", ok, reason)
		}
	})

	t.Run("non-rpm account always schedulable", func(t *testing.T) {
		svc, _ := newOpenAIRPMTestService(t, map[int64]int{999: 9999})
		apikey := &Account{ID: 999, Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
		if ok, reason := svc.isOpenAIAccountRPMSchedulable(context.Background(), apikey, false); !ok || reason != "" {
			t.Errorf("api-key account must bypass RPM, got (%v, %q)", ok, reason)
		}
		noLimit := &Account{ID: 243, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
		if ok, reason := svc.isOpenAIAccountRPMSchedulable(context.Background(), noLimit, false); !ok || reason != "" {
			t.Errorf("zero base_rpm must bypass RPM, got (%v, %q)", ok, reason)
		}
	})

	t.Run("prefetch context wins over cache", func(t *testing.T) {
		svc, _ := newOpenAIRPMTestService(t, map[int64]int{account.ID: 100})
		ctx := withAccountsRPMPrefetch(context.Background(), svc.rpmCache, []Account{})
		// prefetch 没有条目时回退 GetRPM：红区
		if ok, _ := svc.isOpenAIAccountRPMSchedulable(ctx, account, false); ok {
			t.Error("cache value 100 must be red zone")
		}
	})
}

func TestOpenAIRequestTreatsAccountAsSticky(t *testing.T) {
	account := &Account{ID: 7}
	base := OpenAIAccountScheduleRequest{}
	if openAIRequestTreatsAccountAsSticky(account, base) {
		t.Error("no sticky ids → not sticky")
	}
	if !openAIRequestTreatsAccountAsSticky(account, OpenAIAccountScheduleRequest{StickyAccountID: 7}) {
		t.Error("StickyAccountID match → sticky")
	}
	if !openAIRequestTreatsAccountAsSticky(account, OpenAIAccountScheduleRequest{GuardianParentAccountID: 7}) {
		t.Error("GuardianParentAccountID match → sticky")
	}
	if !openAIRequestTreatsAccountAsSticky(account, OpenAIAccountScheduleRequest{StickyPreviousAccountID: 7}) {
		t.Error("StickyPreviousAccountID match → sticky")
	}
	if openAIRequestTreatsAccountAsSticky(account, OpenAIAccountScheduleRequest{StickyAccountID: 8}) {
		t.Error("other account's sticky id → not sticky")
	}
	if openAIRequestTreatsAccountAsSticky(nil, OpenAIAccountScheduleRequest{StickyAccountID: 7}) {
		t.Error("nil account → not sticky")
	}
}

func TestOpenAIGatewayServiceIncrementAccountRPM(t *testing.T) {
	svc, cache := newOpenAIRPMTestService(t, nil)
	if err := svc.IncrementAccountRPM(context.Background(), 243); err != nil {
		t.Fatalf("increment failed: %v", err)
	}
	if cache.counts[243] != 1 {
		t.Fatalf("count = %d, want 1", cache.counts[243])
	}
	if err := svc.IncrementAccountRPM(context.Background(), 243); err != nil {
		t.Fatalf("increment failed: %v", err)
	}
	if cache.counts[243] != 2 {
		t.Fatalf("count = %d, want 2", cache.counts[243])
	}
	noCache := &OpenAIGatewayService{}
	if err := noCache.IncrementAccountRPM(context.Background(), 1); err != nil {
		t.Errorf("nil cache must no-op, got %v", err)
	}
}
