package service

import (
	"fmt"
	"hash/fnv"
	"strings"
	"sync/atomic"
)

// codexPersonaSuffixes 是账号人设的 UA 环境段候选池，全部取自真实 Codex 流量
// 审计样例（internal/pkg/openai/request_test.go / request_identity_test.go）中出现
// 过的 OS/架构/终端组合，外加与编译期规范 UA 一致的兜底项。
//
// 人设只替换 UA 的环境段（第一个 " (" 之后的部分）：originator 与版本段仍由规范
// 身份链重建（版本自动同步、originator 配对校验不受影响）。效果是同一账号永远
// 呈现同一台"机器"，而不同账号呈现真实人群的 OS/终端多样性——避免 N 个账号共享
// 完全相同 UA 的克隆集群特征。
var codexPersonaSuffixes = []string{
	" (Ubuntu 22.4.0; x86_64) xterm-256color", // 与编译期规范 UA 一致
	" (Ubuntu 22.4.0; x86_64) screen",
	" (Ubuntu 24.4.0; x86_64) tmux",
	" (Mac OS 15.5.0; arm64) ghostty/1.3.1",
	" (Mac OS 14.6.1; arm64) Apple_Terminal/453",
	" (Mac OS 26.1.0; arm64) iTerm.app/3.4.22",
	" (Mac OS X 14.0; arm64) iTerm",
	" (Mac OS 15.3.2; arm64) Terminal",
}

// codexPersonaDiversity 控制「账号人设多样化」：关闭时所有账号回退到单一规范 UA。
// 由 gateway.disable_codex_persona_diversity 取反后在服务构造时发布，默认开启。
var codexPersonaDiversity = func() *atomic.Bool {
	v := &atomic.Bool{}
	v.Store(true)
	return v
}()

// SetCodexPersonaDiversityEnabled 发布账号人设多样化开关。与身份强制统一开关
// （SetCodexIdentityEnforcementEnabled）同构：enforceCodexIdentityHeaders 系列是
// 纯函数收口点，拿不到配置，由持有配置的服务在构造时发布进程级快照。
func SetCodexPersonaDiversityEnabled(enabled bool) {
	codexPersonaDiversity.Store(enabled)
}

// codexAccountPersonaUserAgent 返回账号的稳定人设 User-Agent：
// 在当前规范 UA（版本自动同步）的基础上，按账号 ID 确定性地替换环境段。
// 人设关闭、账号 ID 无效或规范 UA 无环境段时原样返回规范 UA。
func codexAccountPersonaUserAgent(accountID int64) string {
	identity := resolveCodexOutboundIdentity("")
	if !codexPersonaDiversity.Load() || accountID <= 0 {
		return identity.userAgent
	}
	base := identity.userAgent
	idx := strings.Index(base, " (")
	if idx < 0 {
		return base
	}
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "codex-persona-v1:%d", accountID)
	suffix := codexPersonaSuffixes[h.Sum32()%uint32(len(codexPersonaSuffixes))]
	return base[:idx] + suffix
}

// codexAccountOverrideUserAgent 是账号级出站 UA 的统一取值顺序：
// 管理员显式配置 > 账号人设 > 规范 UA（由调用方自行回退）。forceCodexCLI 场景
// 由调用方判断（返回空串以回退规范 UA），保持与 codexIdentityOverrideUA 相同的
// 优先级语义，供探针等无 s.cfg 句柄的路径复用。
func codexAccountOverrideUserAgent(account *Account) string {
	if account == nil {
		return ""
	}
	if ua := strings.TrimSpace(account.GetOpenAIUserAgent()); ua != "" {
		return ua
	}
	return codexAccountPersonaUserAgent(account.ID)
}
