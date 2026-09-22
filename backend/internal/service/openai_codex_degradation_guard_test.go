package service

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestCodexModelGeneration(t *testing.T) {
	cases := []struct {
		model string
		want  float64
		ok    bool
	}{
		{"gpt-6-astra", 6, true},
		{"gpt-6", 6, true},
		{"gpt-5.6-luna", 5.6, true},
		{"gpt-5.1-codex", 5.1, true},
		{"gpt-5", 5, true},
		{"gpt-4o", 4, true},
		{"GPT-6-Astra", 6, true},
		{"gpt-4.1", 4.1, true},
		// 非 gpt-* 家族不参与比较
		{"o3", 0, false},
		{"o4-mini", 0, false},
		{"chatgpt-4o-latest", 0, false},
		{"", 0, false},
		// 形态异常：无数字 / 悬空小数点
		{"gpt-x", 0, false},
		{"gpt-5.", 0, false},
	}
	for _, tc := range cases {
		got, ok := codexModelGeneration(tc.model)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("codexModelGeneration(%q) = (%v, %v), want (%v, %v)", tc.model, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsOpenAICodexModelDowngrade(t *testing.T) {
	cases := []struct {
		sent, got string
		want      bool
	}{
		// 线上实测的降级形态：请求 6 代，上游换成 5.6 代
		{"gpt-6-astra", "gpt-5.6-luna", true},
		{"gpt-6", "gpt-5.6-luna", true},
		{"gpt-5.6-sol", "gpt-5", true},
		// 升级与改名放行
		{"gpt-5.6-sol", "gpt-6-sol", false},
		{"gpt-6-astra", "gpt-6-luna", false},
		{"gpt-6-astra", "gpt-6-astra", false},
		{"gpt-6-astra", "gpt-6.1", false},
		// 任一侧无法解析代际 → 不判断
		{"gpt-6-astra", "o3", false},
		{"o3", "gpt-5.6-luna", false},
		{"gpt-6-astra", "", false},
	}
	for _, tc := range cases {
		if got := isOpenAICodexModelDowngrade(tc.sent, tc.got); got != tc.want {
			t.Errorf("isOpenAICodexModelDowngrade(%q, %q) = %v, want %v", tc.sent, tc.got, got, tc.want)
		}
	}
}

func TestCodexDegradationGuardApplies(t *testing.T) {
	openAIOAuth := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	openAIAPIKey := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	anthropicOAuth := &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth}

	if !codexDegradationGuardApplies(openAIOAuth, "gpt-6-astra") {
		t.Error("OpenAI OAuth account with sent model should be guarded")
	}
	if codexDegradationGuardApplies(openAIAPIKey, "gpt-6-astra") {
		t.Error("API-key account must not be guarded (channel mapping is contractual)")
	}
	if codexDegradationGuardApplies(anthropicOAuth, "claude-x") {
		t.Error("Anthropic account is out of scope")
	}
	if codexDegradationGuardApplies(openAIOAuth, "  ") {
		t.Error("Empty sent model disables the guard")
	}

	prev := codexDegradationGuardEnabled.Load()
	codexDegradationGuardEnabled.Store(false)
	if codexDegradationGuardApplies(openAIOAuth, "gpt-6-astra") {
		t.Error("Disabled switch must disable the guard")
	}
	codexDegradationGuardEnabled.Store(prev)
}

func TestCodexDegradationGuardConsumeBudget(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)
	for i := 0; i < codexDegradationGuardMaxFailovers; i++ {
		if !codexDegradationGuardConsumeBudget(c) {
			t.Fatalf("attempt %d should be within budget", i+1)
		}
	}
	if codexDegradationGuardConsumeBudget(c) {
		t.Error("budget must be exhausted after max failovers")
	}
	if codexDegradationGuardConsumeBudget(c) {
		t.Error("budget stays exhausted (idempotent)")
	}
}

func TestNewCodexDegradationGuardFailoverError(t *testing.T) {
	err := newCodexDegradationGuardFailoverError(&Account{ID: 243, Name: "official-243"}, "gpt-6-astra", "gpt-5.6-luna")
	if err.RetryableOnSameAccount {
		t.Error("downgrade must fail over to a different account")
	}
	if !err.RequestScopedTransient {
		t.Error("downgrade is request-scoped: must not feed account health metrics")
	}
	if err.NextAccountAction != NextAccountRetry {
		t.Error("explicit next-account retry expected")
	}
	if !err.ShouldRetryNextAccount() {
		t.Error("ShouldRetryNextAccount must hold")
	}
	if err.SafeToFailoverAfterWrite {
		t.Error("guard fires only pre-output; SafeToFailoverAfterWrite must be false")
	}
	if err.ClientStatusCode != http.StatusServiceUnavailable {
		t.Errorf("client status = %d, want 503", err.ClientStatusCode)
	}
	if err.Reason != codexDegradationGuardReason {
		t.Errorf("reason = %v, want %v", err.Reason, codexDegradationGuardReason)
	}
}

func TestCodexDegradationGuardCheckStream(t *testing.T) {
	svc := &OpenAIGatewayService{}
	account := &Account{ID: 243, Name: "official-243", Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	created := []byte(`{"type":"response.created","response":{"id":"resp_1","model":"gpt-5.6-luna"}}`)
	sameModel := []byte(`{"type":"response.created","response":{"id":"resp_2","model":"gpt-6-astra"}}`)
	modelFree := []byte(`{"type":"response.in_progress","response":{"id":"resp_3"}}`)

	t.Run("downgrade triggers failover before any client byte", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		checked := false
		err := svc.codexDegradationGuardCheckStream(c, account, true, &checked, created, "gpt-6-astra")
		if err == nil {
			t.Fatal("downgrade must produce a failover error")
		}
		if !checked {
			t.Error("model declaration should mark the stream as checked")
		}
	})

	t.Run("same-generation model passes", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		checked := false
		if err := svc.codexDegradationGuardCheckStream(c, account, true, &checked, sameModel, "gpt-6-astra"); err != nil {
			t.Fatalf("same model must pass, got %v", err)
		}
		if !checked {
			t.Error("model declaration should still mark the stream as checked")
		}
	})

	t.Run("model-free events do not consume the check", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		checked := false
		if err := svc.codexDegradationGuardCheckStream(c, account, true, &checked, modelFree, "gpt-6-astra"); err != nil {
			t.Fatalf("model-free event must be ignored, got %v", err)
		}
		if checked {
			t.Error("model-free event must not mark the stream as checked")
		}
	})

	t.Run("checked stream never re-evaluates", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		checked := true
		if err := svc.codexDegradationGuardCheckStream(c, account, true, &checked, created, "gpt-6-astra"); err != nil {
			t.Fatalf("already-checked stream must short-circuit, got %v", err)
		}
	})

	t.Run("ineligible account never checks", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		checked := false
		if err := svc.codexDegradationGuardCheckStream(c, account, false, &checked, created, "gpt-6-astra"); err != nil {
			t.Fatalf("ineligible account must be ignored, got %v", err)
		}
		if checked {
			t.Error("ineligible account must not mark checked")
		}
	})

	t.Run("budget exhaustion serves degraded result", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		for i := 0; i < codexDegradationGuardMaxFailovers; i++ {
			if !codexDegradationGuardConsumeBudget(c) {
				t.Fatalf("attempt %d should be within budget", i+1)
			}
		}
		checked := false
		if err := svc.codexDegradationGuardCheckStream(c, account, true, &checked, created, "gpt-6-astra"); err != nil {
			t.Fatalf("exhausted budget must serve the degraded result, got %v", err)
		}
	})
}

func TestCodexDegradationGuardCheckBody(t *testing.T) {
	svc := &OpenAIGatewayService{}
	account := &Account{ID: 213, Name: "official-213", Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	t.Run("json body downgrade fails over", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		if err := svc.codexDegradationGuardCheckBody(c, account, "gpt-6-astra", "gpt-5.6-luna"); err == nil {
			t.Fatal("downgrade must produce a failover error")
		}
	})

	t.Run("same model passes", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		if err := svc.codexDegradationGuardCheckBody(c, account, "gpt-6-astra", "gpt-6-astra"); err != nil {
			t.Fatalf("same model must pass, got %v", err)
		}
	})

	t.Run("empty observed model passes", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		if err := svc.codexDegradationGuardCheckBody(c, account, "gpt-6-astra", ""); err != nil {
			t.Fatalf("empty model must pass, got %v", err)
		}
	})

	t.Run("anthropic account out of scope", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		anthropic := &Account{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
		if err := svc.codexDegradationGuardCheckBody(c, anthropic, "gpt-6-astra", "gpt-5.6-luna"); err != nil {
			t.Fatalf("anthropic account must be ignored, got %v", err)
		}
	})
}
