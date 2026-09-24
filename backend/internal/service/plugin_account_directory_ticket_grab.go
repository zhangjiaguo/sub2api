package service

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// ticketGrabMetadataTTL 与打票服务自身的配置缓存周期一致（30 秒）：宿主每次列举
// 账号目录时重读设置的成本已被缓存摊平，且与打票调度看到的状态最多滞后一个周期。
const ticketGrabMetadataTTL = 30 * time.Second

// ticketGrabMetadataKey 是注入账号 MetadataJSON 的宿主计算键。MetadataJSON 的键
// 通常是账号模型字段名；此键是宿主侧横切状态（打票占用）的唯一例外，供出口类
// 插件把打票账号从可绑定集合中排除。纯加法：不认识该键的插件不受影响。
const ticketGrabMetadataKey = "ticket_grab"

// TicketGrabAwareAccountDirectory 装饰宿主账号目录：打票占用中的账号
// （openai_ticket_grab 设置的 account_ids，attach_to_forward 开启时并入
// attach_account_ids）在 MetadataJSON 里被标记 ticket_grab=true。它只改写可读
// 元数据，不触碰凭据解析通道；设置读取失败时静默退化为「无标记」，绝不阻断目录。
type TicketGrabAwareAccountDirectory struct {
	base     PluginAccountDirectory
	settings SettingRepository

	mu        sync.Mutex
	loadedAt  time.Time
	cachedSet map[int64]bool
}

// NewTicketGrabAwareAccountDirectory 包装 base 目录并注入打票占用标记。
func NewTicketGrabAwareAccountDirectory(base PluginAccountDirectory, settings SettingRepository) *TicketGrabAwareAccountDirectory {
	return &TicketGrabAwareAccountDirectory{base: base, settings: settings}
}

// ListPluginAccounts 在 base 结果之上标注打票占用账号。
func (d *TicketGrabAwareAccountDirectory) ListPluginAccounts(ctx context.Context, scope PluginAccountScope, platform, accountType string) ([]PluginAccountInfo, error) {
	infos, err := d.base.ListPluginAccounts(ctx, scope, platform, accountType)
	if err != nil || len(infos) == 0 {
		return infos, err
	}
	busy := d.ticketGrabSet(ctx)
	if len(busy) == 0 {
		return infos, nil
	}
	for i := range infos {
		if !busy[infos[i].ID] {
			continue
		}
		infos[i].MetadataJSON = injectTicketGrabFlag(infos[i].MetadataJSON)
	}
	return infos, nil
}

// ResolvePluginOutboundIdentity 原样透传给 base（凭据通道不做任何改写）。
func (d *TicketGrabAwareAccountDirectory) ResolvePluginOutboundIdentity(ctx context.Context, scope PluginAccountScope, accountID int64) (*PluginOutboundIdentity, error) {
	return d.base.ResolvePluginOutboundIdentity(ctx, scope, accountID)
}

// ticketGrabSet 读取打票设置并汇总占用账号集合（带缓存；失败时返回空集）。
func (d *TicketGrabAwareAccountDirectory) ticketGrabSet(ctx context.Context) map[int64]bool {
	d.mu.Lock()
	if !d.loadedAt.IsZero() && time.Since(d.loadedAt) < ticketGrabMetadataTTL {
		cached := d.cachedSet
		d.mu.Unlock()
		return cached
	}
	d.mu.Unlock()

	set := map[int64]bool{}
	if d.settings != nil {
		var settings OpenAITicketGrabSettings
		if raw, err := d.settings.GetValue(ctx, SettingKeyOpenAITicketGrab); err == nil && raw != "" {
			if err := json.Unmarshal([]byte(raw), &settings); err != nil {
				settings = OpenAITicketGrabSettings{}
			}
		}
		if settings.Enabled {
			for _, id := range settings.AccountIDs {
				set[id] = true
			}
			if settings.AttachToForward {
				for _, id := range settings.AttachAccountIDs {
					set[id] = true
				}
			}
		}
	}

	d.mu.Lock()
	d.loadedAt = time.Now()
	d.cachedSet = set
	d.mu.Unlock()
	return set
}

// injectTicketGrabFlag 把 ticket_grab=true 合并进 MetadataJSON 对象。原对象解析
// 失败（非对象/为空）时返回携带该键的新对象，保证标记不因快照形状异常而丢失。
func injectTicketGrabFlag(metadata []byte) []byte {
	obj := map[string]any{}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &obj)
	}
	obj[ticketGrabMetadataKey] = true
	data, err := json.Marshal(obj)
	if err != nil {
		return metadata
	}
	return data
}
