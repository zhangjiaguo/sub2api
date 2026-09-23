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

func TestOpenAITicketParseRetryAfter(t *testing.T) {
	assert.Equal(t, 90*time.Second, openAITicketParseRetryAfter("90"))
	assert.Equal(t, time.Duration(0), openAITicketParseRetryAfter(""))
	assert.Equal(t, time.Duration(0), openAITicketParseRetryAfter("abc"))
	// HTTP 日期：过去的日期不应产生负延迟
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	assert.Equal(t, time.Duration(0), openAITicketParseRetryAfter(past))
}
