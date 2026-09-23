package admin

import (
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// OpenAITicketGrabHandler 处理打票（turn-state 采集）的 HTTP 请求。
type OpenAITicketGrabHandler struct {
	service *service.OpenAITicketGrabService
}

// NewOpenAITicketGrabHandler 创建打票处理器。
func NewOpenAITicketGrabHandler(service *service.OpenAITicketGrabService) *OpenAITicketGrabHandler {
	return &OpenAITicketGrabHandler{service: service}
}

// UpdateSettingsRequest 保存打票配置请求。
type UpdateOpenAITicketGrabSettingsRequest struct {
	Enabled           bool    `json:"enabled"`
	ProxyURL          string  `json:"proxy_url"`
	Model             string  `json:"model"`
	AccountIDs        []int64 `json:"account_ids"`
	LeadSeconds       int     `json:"lead_seconds"`
	TTLSeconds        int     `json:"ttl_seconds"`
	MinIntervalSecond int     `json:"min_interval_seconds"`
	ProbeTimeoutSecs  int     `json:"probe_timeout_seconds"`
	ExpectedLength    int     `json:"expected_length"`
	ExpectedBlocks    int     `json:"expected_blocks"`
	MaxProbesPerRound int     `json:"max_probes_per_round"`
	AttachToForward   bool    `json:"attach_to_forward"`
	AttachAccountIDs  []int64 `json:"attach_account_ids"`
}

// GetSettings 获取打票配置
// GET /api/v1/admin/openai/ticket-grab/config
func (h *OpenAITicketGrabHandler) GetSettings(c *gin.Context) {
	response.Success(c, h.service.GetSettings(c.Request.Context()))
}

// UpdateSettings 保存打票配置
// PUT /api/v1/admin/openai/ticket-grab/config
func (h *OpenAITicketGrabHandler) UpdateSettings(c *gin.Context) {
	var req UpdateOpenAITicketGrabSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	settings := service.OpenAITicketGrabSettings{
		Enabled:           req.Enabled,
		ProxyURL:          req.ProxyURL,
		Model:             req.Model,
		AccountIDs:        req.AccountIDs,
		LeadSeconds:       req.LeadSeconds,
		TTLSeconds:        req.TTLSeconds,
		MinIntervalSecond: req.MinIntervalSecond,
		ProbeTimeoutSecs:  req.ProbeTimeoutSecs,
		ExpectedLength:    req.ExpectedLength,
		ExpectedBlocks:    req.ExpectedBlocks,
		MaxProbesPerRound: req.MaxProbesPerRound,
		AttachToForward:   req.AttachToForward,
		AttachAccountIDs:  req.AttachAccountIDs,
	}
	if err := h.service.UpdateSettings(c.Request.Context(), settings); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, settings)
}

// TestProxyRequest 测试动态代理请求。
type TestOpenAITicketGrabProxyRequest struct {
	ProxyURL string `json:"proxy_url" binding:"required"`
}

// TestProxy 测试动态代理连通性并采样出口 IP
// POST /api/v1/admin/openai/ticket-grab/test-proxy
func (h *OpenAITicketGrabHandler) TestProxy(c *gin.Context) {
	var req TestOpenAITicketGrabProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	samples, err := h.service.TestProxy(c.Request.Context(), req.ProxyURL)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, gin.H{"samples": samples})
}

// Status 各账号当前票据与调度状态
// GET /api/v1/admin/openai/ticket-grab/status
func (h *OpenAITicketGrabHandler) Status(c *gin.Context) {
	statuses, err := h.service.Status(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, statuses)
}

// RunNowRequest 手动打票请求。
type RunOpenAITicketGrabNowRequest struct {
	AccountID int64 `json:"account_id" binding:"required"`
}

// RunNow 手动触发一次打票
// POST /api/v1/admin/openai/ticket-grab/run
func (h *OpenAITicketGrabHandler) RunNow(c *gin.Context) {
	var req RunOpenAITicketGrabNowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	if err := h.service.RunNow(c.Request.Context(), req.AccountID); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, gin.H{"message": "打票成功"})
}

// ListLogs 打票日志
// GET /api/v1/admin/openai/ticket-grab/logs?account_id=&limit=&offset=
func (h *OpenAITicketGrabHandler) ListLogs(c *gin.Context) {
	var accountID int64
	if raw := c.Query("account_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 0 {
			response.BadRequest(c, "Invalid account_id")
			return
		}
		accountID = id
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	logs, err := h.service.ListLogs(c.Request.Context(), accountID, limit, offset)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, logs)
}
