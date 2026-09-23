package service

import "net/http"

func (s *OpenAIGatewayService) SetPluginManager(manager *PluginManager) {
	s.pluginManager = manager
}

// SetTLSFingerprintProfileService 注入 TLS 指纹模板服务，供 OpenAI 出站请求
// 按 account extra 的 enable_tls_fingerprint 开关伪装 Codex CLI 握手特征。
func (s *OpenAIGatewayService) SetTLSFingerprintProfileService(profileService *TLSFingerprintProfileService) {
	s.tlsFPProfileService = profileService
}

// SetTicketEgressRouter 注入打票出口路由：命中灰度账号时，真实转发改走
// 「固定出口槽位」并附带该出口铸造的 turn-state 票据（票/出口严格一致，
// 见 openai_ticket_egress.go）。未注入或未命中时出站行为与原先完全一致。
func (s *OpenAIGatewayService) SetTicketEgressRouter(router OpenAITicketEgressRouter) {
	s.ticketEgress = router
}

// doOpenAIUpstream 只在 OpenAI OAuth 能力绑定已启用时把真实请求交给插件。
// 插件返回标准 http.Response，响应解析、错误映射、SSE 和计费仍由现有核心链处理。
// 账号启用 TLS 指纹时走 DoWithTLS（真实 codex 为 OpenSSL/HTTP1.1，无 ALPN），
// 否则保持原有 Do 行为，账号零配置不产生任何变化。
func (s *OpenAIGatewayService) doOpenAIUpstream(request *http.Request, proxyURL string, account *Account) (*http.Response, error) {
	if s.pluginManager != nil {
		response, handled, err := s.pluginManager.RoundTripOpenAIOAuth(request.Context(), request, proxyURL, account)
		if handled {
			return response, err
		}
	}
	// 打票出口接入：灰度账号的请求经「票据 + 固定出口」槽位出站；
	// 槽位连接本身即账号解析出的 TLS 指纹（含 Codex utls）。
	if s.ticketEgress != nil && account != nil {
		if handle := s.ticketEgress.AcquireTicketEgress(request.Context(), account); handle != nil {
			return handle.RoundTrip(request)
		}
	}
	if s.tlsFPProfileService != nil {
		if profile := s.tlsFPProfileService.ResolveTLSProfile(account); profile != nil {
			return s.httpUpstream.DoWithTLS(request, proxyURL, account.ID, account.Concurrency, profile)
		}
	}
	return s.httpUpstream.Do(request, proxyURL, account.ID, account.Concurrency)
}

// doOpenAIAccountTestUpstream 让 OpenAI OAuth 账号测试与真实转发使用同一插件路径。
// API Key 和未命中插件的账号保持各自原有的 HTTPUpstream 行为。
func (s *AccountTestService) doOpenAIAccountTestUpstream(
	request *http.Request,
	proxyURL string,
	account *Account,
	useTLSFallback bool,
) (*http.Response, error) {
	if s.pluginManager != nil {
		response, handled, err := s.pluginManager.RoundTripOpenAIOAuth(request.Context(), request, proxyURL, account)
		if handled {
			return response, err
		}
	}
	if useTLSFallback {
		return s.httpUpstream.DoWithTLS(
			request,
			proxyURL,
			account.ID,
			account.Concurrency,
			s.tlsFPProfileService.ResolveTLSProfile(account),
		)
	}
	return s.httpUpstream.Do(request, proxyURL, account.ID, account.Concurrency)
}
