package service

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestTicketState 构造一个合法形态的 turn-state：
// 0x80 前缀 + 8 字节大端签发时间戳 + 净荷，总长 57 + 16*blocks。
func buildTestTicketState(blocks int, issued time.Time) string {
	raw := make([]byte, 57+16*blocks)
	raw[0] = 0x80
	binary.BigEndian.PutUint64(raw[1:9], uint64(issued.Unix()))
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestParseOpenAITicketState(t *testing.T) {
	now := time.Now()

	t.Run("gpt-6-astra 实测形态 780 字符 / 33 块", func(t *testing.T) {
		state := buildTestTicketState(33, now)
		require.Len(t, state, 780)
		parsed, err := parseOpenAITicketState(state)
		require.NoError(t, err)
		assert.Equal(t, 33, parsed.blocks)
		assert.WithinDuration(t, now.Truncate(time.Second), parsed.issuedAt, 2*time.Second)
	})

	t.Run("历史形态 10 块（README 的 292 为含 padding 长度）", func(t *testing.T) {
		state := buildTestTicketState(10, now)
		require.Len(t, state, 290)
		parsed, err := parseOpenAITicketState(state)
		require.NoError(t, err)
		assert.Equal(t, 10, parsed.blocks)
		// 带 padding 的写法（≤2 个 '='）同样接受。
		padded := state + "=="
		parsed, err = parseOpenAITicketState(padded)
		require.NoError(t, err)
		assert.Equal(t, 10, parsed.blocks)
	})

	t.Run("空值", func(t *testing.T) {
		_, err := parseOpenAITicketState("")
		require.Error(t, err)
		_, err = parseOpenAITicketState("   ")
		require.Error(t, err)
	})

	t.Run("前缀错误", func(t *testing.T) {
		raw := make([]byte, 57+16*3)
		binary.BigEndian.PutUint64(raw[1:9], uint64(now.Unix()))
		_, err := parseOpenAITicketState(base64.RawURLEncoding.EncodeToString(raw))
		require.Error(t, err)
	})

	t.Run("块对齐错误", func(t *testing.T) {
		raw := make([]byte, 58) // 57+1：不对齐 16 字节块
		raw[0] = 0x80
		binary.BigEndian.PutUint64(raw[1:9], uint64(now.Unix()))
		_, err := parseOpenAITicketState(base64.RawURLEncoding.EncodeToString(raw))
		require.Error(t, err)
	})

	t.Run("时间戳超出合理范围", func(t *testing.T) {
		// 2000 年（早于 2020 门槛）
		ancient := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		_, err := parseOpenAITicketState(buildTestTicketState(3, ancient))
		require.Error(t, err)
		// 2120 年
		far := time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC)
		_, err = parseOpenAITicketState(buildTestTicketState(3, far))
		require.Error(t, err)
	})

	t.Run("含空白字符拒绝", func(t *testing.T) {
		state := buildTestTicketState(3, now)
		_, err := parseOpenAITicketState(state[:100] + " " + state[100:])
		require.Error(t, err)
	})

	t.Run("超长拒绝", func(t *testing.T) {
		_, err := parseOpenAITicketState(strings.Repeat("A", 2049))
		require.Error(t, err)
	})
}

func TestOpenAITicketGrabSettingsValidate(t *testing.T) {
	t.Run("默认值合法", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		require.NoError(t, settings.Validate())
		assert.Equal(t, 780, settings.ExpectedLength)
		assert.Equal(t, 33, settings.ExpectedBlocks)
		assert.Equal(t, "gpt-6-astra", settings.Model)
	})

	t.Run("启用时缺代理报错", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.Enabled = true
		settings.AccountIDs = []int64{1}
		err := settings.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "动态代理")
	})

	t.Run("启用时缺账号报错", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.Enabled = true
		settings.ProxyURL = "socks5h://user:pass@host:10000"
		err := settings.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "账号")
	})

	t.Run("代理协议白名单", func(t *testing.T) {
		for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
			_, err := parseOpenAITicketProxyURL(scheme + "://u:p@us.example.com:10000")
			assert.NoError(t, err, scheme)
		}
		_, err := parseOpenAITicketProxyURL("grpc://us.example.com:10000")
		assert.Error(t, err)
		_, err = parseOpenAITicketProxyURL("http://")
		assert.Error(t, err)
	})

	t.Run("边界收敛", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.LeadSeconds = 1
		settings.MinIntervalSecond = 5
		settings.ProbeTimeoutSecs = 999
		settings.MaxProbesPerRound = 0
		settings.ExpectedLength = -1
		require.NoError(t, settings.Validate())
		assert.Equal(t, 30, settings.LeadSeconds)
		assert.Equal(t, 30, settings.MinIntervalSecond)
		assert.Equal(t, 300, settings.ProbeTimeoutSecs)
		assert.Equal(t, 1, settings.MaxProbesPerRound)
		assert.Equal(t, 780, settings.ExpectedLength)
	})

	t.Run("lead 超过 TTL 时收敛 TTL", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.LeadSeconds = 5000
		require.NoError(t, settings.Validate())
		assert.Equal(t, 5000, settings.TTLSeconds)
	})
}

func TestClassifyOpenAITicketProbe(t *testing.T) {
	now := time.Now()
	settings := DefaultOpenAITicketGrabSettings()
	valid := buildTestTicketState(33, now)
	mismatch := buildTestTicketState(10, now)
	stale := buildTestTicketState(33, now.Add(-time.Hour))

	t.Run("正常完成", func(t *testing.T) {
		result, detail := classifyOpenAITicketProbe(valid, true, now, settings)
		assert.Equal(t, "accepted", result)
		assert.Empty(t, detail)
	})

	t.Run("流提前结束但票据已铸造（实测场景）", func(t *testing.T) {
		result, detail := classifyOpenAITicketProbe(valid, false, now, settings)
		assert.Equal(t, "accepted", result)
		assert.Contains(t, detail, "提前结束")
	})

	t.Run("形态不符", func(t *testing.T) {
		result, _ := classifyOpenAITicketProbe(mismatch, true, now, settings)
		assert.Equal(t, "shape_mismatch", result)
	})

	t.Run("时间戳过期", func(t *testing.T) {
		result, _ := classifyOpenAITicketProbe(stale, true, now, settings)
		assert.Equal(t, "stale_state", result)
	})

	t.Run("缺少票据", func(t *testing.T) {
		result, _ := classifyOpenAITicketProbe("", true, now, settings)
		assert.Equal(t, "missing_state", result)
	})

	t.Run("封装非法", func(t *testing.T) {
		result, _ := classifyOpenAITicketProbe("!!!not-base64!!!", true, now, settings)
		assert.Equal(t, "state_invalid", result)
	})

	t.Run("时钟小幅偏差仍新鲜", func(t *testing.T) {
		// 上游时钟快 2 分钟（在允许偏差内）
		result, _ := classifyOpenAITicketProbe(buildTestTicketState(33, now.Add(2*time.Minute)), true, now, settings)
		assert.Equal(t, "accepted", result)
	})
}

func TestOpenAITicketParseRetryAfter(t *testing.T) {
	assert.Equal(t, 90*time.Second, openAITicketParseRetryAfter("90"))
	assert.Equal(t, time.Duration(0), openAITicketParseRetryAfter(""))
	assert.Equal(t, time.Duration(0), openAITicketParseRetryAfter("abc"))
	// HTTP 日期：过去的日期不应产生负延迟
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	assert.Equal(t, time.Duration(0), openAITicketParseRetryAfter(past))
}

func TestOpenAITicketGrabCooldownForResult(t *testing.T) {
	settings := DefaultOpenAITicketGrabSettings() // MinIntervalSecond=180

	t.Run("403 出口被拒仅按最小间隔轮换，不做长冷却", func(t *testing.T) {
		cooldown, kind := openAITicketGrabCooldownForResult("http_403", 0, settings)
		assert.Equal(t, 180*time.Second, cooldown)
		assert.Empty(t, kind)
	})

	t.Run("401 凭据失效长冷却", func(t *testing.T) {
		cooldown, kind := openAITicketGrabCooldownForResult("http_401", 0, settings)
		assert.Equal(t, openAITicketGrabAuthCooldown, cooldown)
		assert.Equal(t, "auth", kind)
	})

	t.Run("429 尊重 Retry-After 下限", func(t *testing.T) {
		cooldown, kind := openAITicketGrabCooldownForResult("http_429", 0, settings)
		assert.Equal(t, openAITicketGrab429Cooldown, cooldown)
		assert.Equal(t, "rate_limit", kind)

		cooldown, kind = openAITicketGrabCooldownForResult("http_429", 45*time.Minute, settings)
		assert.Equal(t, 45*time.Minute, cooldown)
		assert.Equal(t, "rate_limit", kind)
	})

	t.Run("网络错误等按最小间隔节奏", func(t *testing.T) {
		for _, result := range []string{"network_error", "request_error", "shape_mismatch", "state_invalid"} {
			cooldown, kind := openAITicketGrabCooldownForResult(result, 0, settings)
			assert.Equal(t, 180*time.Second, cooldown, result)
			assert.Empty(t, kind, result)
		}
	})
}
