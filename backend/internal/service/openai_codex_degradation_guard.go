package service

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
)

// 降级守卫（degradation guard）：OpenAI 官方 OAuth 账号有时会把 gpt-6-astra
// 静默降级为 gpt-5.6-luna 等上一代模型（上游容量调度行为，响应里只有 model
// 字段不一致，无任何错误信号）。守卫在首个携带 model 声明的 SSE 事件处比对
// 代际：若上游声明的是比请求更低代际的模型，且此时还没有任何字节写给客户端
// （Responses 流的前导事件全部缓存在 pendingLines，客户端零字节），则构造
// failover 错误换号重试，而不是把降级结果发给用户。
//
// 换号预算：每个客户端请求最多因降级换号 codexDegradationGuardMaxFailovers
// 次（跨账号共享，计数挂在 gin context 上）。预算耗尽后仍遇降级则照常放行，
// 保证请求最终有结果（宁降级、不无限循环）。
//
// 仅对 OAuth 官号生效：API-key 上游的模型替换是渠道映射的契约行为，不参与
// 判断。代际相同的不同代号（如同一代内的 astra↔luna 改名）不算降级，避免
// 上游正常改名引发误杀。
const (
	// codexDegradationGuardMaxFailovers 是单个客户端请求因模型降级而换号的最大次数。
	codexDegradationGuardMaxFailovers = 2
	// codexDegradationGuardRetryContextKey 记录当前客户端请求已用掉的降级换号次数。
	codexDegradationGuardRetryContextKey = "codex_degradation_guard_failovers"
	// codexDegradationGuardClientMessage 是降级换号预算耗尽且再无可用账号时的下游提示。
	codexDegradationGuardClientMessage = "Upstream degraded the requested model and no healthy account could serve it"
)

// codexDegradationGuardReason 标识降级守卫触发的 failover 分类。
var codexDegradationGuardReason = GatewayFailureReason("codex_model_degradation")

// codexDegradationGuardEnabled 控制降级守卫总开关。默认开启；配置键
// gateway.disable_codex_degradation_guard 置 true 可关闭（取反义命名保证
// 零值安全，与 disable_codex_persona_diversity 同构）。
var codexDegradationGuardEnabled = func() *atomic.Bool {
	var v atomic.Bool
	v.Store(true)
	return &v
}()

// SetCodexDegradationGuardEnabled 发布进程级降级守卫开关快照（构造 GatewayService 时调用）。
func SetCodexDegradationGuardEnabled(enabled bool) {
	codexDegradationGuardEnabled.Store(enabled)
}

// codexDegradationGuardApplies 报告该转发尝试是否参与降级守卫：
// 开关开启 + OpenAI OAuth 官号 + 已知发送模型。
func codexDegradationGuardApplies(account *Account, sentModel string) bool {
	if !codexDegradationGuardEnabled.Load() {
		return false
	}
	if account == nil || account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth {
		return false
	}
	return strings.TrimSpace(sentModel) != ""
}

// codexModelGeneration 从模型名解析可比较的代际数值。
// "gpt-6-astra"→6, "gpt-5.6-luna"→5.6, "gpt-6"→6, "gpt-4o"→4。
// 非 gpt-* 命名（o3 等）返回 ok=false，调用方跳过比较。
func codexModelGeneration(model string) (float64, bool) {
	name := strings.ToLower(strings.TrimSpace(model))
	if !strings.HasPrefix(name, "gpt-") {
		return 0, false
	}
	rest := name[len("gpt-"):]
	// 收集前导数字与至多一个小数点，忽略其后的代号后缀。
	var numeric []byte
	dots := 0
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		if ch >= '0' && ch <= '9' {
			numeric = append(numeric, ch)
			continue
		}
		if ch == '.' && dots == 0 && len(numeric) > 0 {
			dots++
			numeric = append(numeric, ch)
			continue
		}
		break
	}
	if len(numeric) == 0 || numeric[len(numeric)-1] == '.' {
		return 0, false
	}
	gen, err := strconv.ParseFloat(string(numeric), 64)
	if err != nil || gen <= 0 {
		return 0, false
	}
	return gen, true
}

// isOpenAICodexModelDowngrade 报告上游声明的模型是否比请求模型代际更低。
// 任一侧无法解析代际、或代际相同/更高时返回 false（升级或改名放行）。
func isOpenAICodexModelDowngrade(sentModel, responseModel string) bool {
	sentGen, okSent := codexModelGeneration(sentModel)
	respGen, okResp := codexModelGeneration(responseModel)
	if !okSent || !okResp {
		return false
	}
	// 代际字符串完全一致时无需再比（常见快路径）。
	if strings.EqualFold(strings.TrimSpace(sentModel), strings.TrimSpace(responseModel)) {
		return false
	}
	return respGen < sentGen
}

// codexDegradationGuardConsumeBudget 消费一次降级换号预算。
// 返回 true 表示还有预算可以换号；false 表示预算已耗尽，只能照常放行降级结果。
func codexDegradationGuardConsumeBudget(c *gin.Context) bool {
	if c == nil {
		return false
	}
	used := 0
	if v, ok := c.Get(codexDegradationGuardRetryContextKey); ok {
		if n, ok := v.(int); ok {
			used = n
		}
	}
	if used >= codexDegradationGuardMaxFailovers {
		return false
	}
	c.Set(codexDegradationGuardRetryContextKey, used+1)
	return true
}

// newCodexDegradationGuardFailoverError 构造降级守卫的 failover 错误。
// 直接构造 UpstreamFailoverError（不经 newOpenAIStreamFailoverErrorWithModel，
// 那条路径会触发账号侧健康副作用——降级是上游容量调度，不应惩罚本账号）：
//   - RetryableOnSameAccount=false：换号才有意义；
//   - RequestScopedTransient=true：请求级瞬时事件，不进入账号失调度量；
//   - NextAccountRetry：显式换号重试；
//   - SafeToFailoverAfterWrite=false：触发点保证客户端零字节。
func newCodexDegradationGuardFailoverError(account *Account, sentModel, responseModel string) *UpstreamFailoverError {
	body := fmt.Sprintf(`{"error":{"type":"upstream_model_degraded","message":"requested %s but upstream assigned %s","requested_model":%q,"assigned_model":%q}}`,
		sentModel, responseModel, sentModel, responseModel)
	return &UpstreamFailoverError{
		StatusCode:             http.StatusServiceUnavailable,
		ResponseBody:           []byte(body),
		RetryableOnSameAccount: false,
		RequestScopedTransient: true,
		SafeToFailoverAfterWrite: false,
		Stage:                  GatewayFailureStageInference,
		Scope:                  GatewayFailureScopeAccount,
		Reason:                 codexDegradationGuardReason,
		NextAccountAction:      NextAccountRetry,
		ClientStatusCode:       http.StatusServiceUnavailable,
		ClientMessage:          codexDegradationGuardClientMessage,
	}
}

// codexDegradationGuardEvaluate 执行共通的降级判定：代际比较 → 预算消费 →
// 构造 failover 错误。预算耗尽时记日志并返回 nil（照常放行降级结果）。
func codexDegradationGuardEvaluate(c *gin.Context, account *Account, sentModel, responseModel string) *UpstreamFailoverError {
	if !isOpenAICodexModelDowngrade(sentModel, responseModel) {
		return nil
	}
	if !codexDegradationGuardConsumeBudget(c) {
		logger.LegacyPrintf("service.openai_gateway",
			"[CodexDegradationGuard] budget exhausted, serving degraded model (account: %s[%d], sent: %s, got: %s)",
			account.Name, account.ID, sentModel, responseModel)
		return nil
	}
	logger.LegacyPrintf("service.openai_gateway",
		"[CodexDegradationGuard] model downgrade detected, failing over (account: %s[%d], sent: %s, got: %s)",
		account.Name, account.ID, sentModel, responseModel)
	return newCodexDegradationGuardFailoverError(account, sentModel, responseModel)
}

// codexDegradationGuardCheckStream 在流式事件循环中执行降级检查。
// 调用点必须保证 clientOutputStarted==false（客户端零字节）。
// checked 为出参避免对同一流重复解析 model。
func (s *OpenAIGatewayService) codexDegradationGuardCheckStream(
	c *gin.Context,
	account *Account,
	eligible bool,
	checked *bool,
	dataBytes []byte,
	sentModel string,
) *UpstreamFailoverError {
	if !eligible || checked == nil || *checked {
		return nil
	}
	responseModel := firstValidTrimmedGJSONString(dataBytes, "response.model", "model")
	if responseModel == "" {
		return nil
	}
	*checked = true
	return codexDegradationGuardEvaluate(c, account, sentModel, responseModel)
}

// codexDegradationGuardCheckBody 在非流式响应上执行降级检查（客户端尚未收到字节）。
// responseModel 由调用方给出：JSON 体取 response.model/model，SSE 文本体取
// observer 汇总的最终声明（observeOpenAISSEBody 已解析）。
func (s *OpenAIGatewayService) codexDegradationGuardCheckBody(
	c *gin.Context,
	account *Account,
	sentModel, responseModel string,
) *UpstreamFailoverError {
	if !codexDegradationGuardApplies(account, sentModel) || responseModel == "" {
		return nil
	}
	return codexDegradationGuardEvaluate(c, account, sentModel, responseModel)
}
