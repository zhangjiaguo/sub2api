package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// 嵌入接口补齐未用到的方法（装饰层只调用 GetValue）。
type fakeTicketGrabSettingRepo struct {
	SettingRepository
	value string
	err   error
}

func (f *fakeTicketGrabSettingRepo) GetValue(_ context.Context, _ string) (string, error) {
	return f.value, f.err
}

type fakeBaseDirectory struct {
	infos     []PluginAccountInfo
	identity  *PluginOutboundIdentity
	resolveID int64
	calls     int
}

func (f *fakeBaseDirectory) ListPluginAccounts(_ context.Context, _ PluginAccountScope, _, _ string) ([]PluginAccountInfo, error) {
	f.calls++
	return f.infos, nil
}

func (f *fakeBaseDirectory) ResolvePluginOutboundIdentity(_ context.Context, _ PluginAccountScope, accountID int64) (*PluginOutboundIdentity, error) {
	f.resolveID = accountID
	return f.identity, nil
}

func ticketGrabSettingsJSON(t *testing.T, s OpenAITicketGrabSettings) string {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func metadataHasTicketGrab(t *testing.T, metadata []byte) bool {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(metadata, &obj); err != nil {
		// nil/非对象 metadata 等价于无标记。
		return false
	}
	value, ok := obj["ticket_grab"].(bool)
	return ok && value
}

// 打票启用时，account_ids（以及 attach 开启时的 attach_account_ids）内的账号被标注
// ticket_grab=true，其余账号的 MetadataJSON 保持原样。
func TestTicketGrabDirectoryAnnotates(t *testing.T) {
	base := &fakeBaseDirectory{infos: []PluginAccountInfo{
		{ID: 133, MetadataJSON: []byte(`{"ID":133,"Name":"a133"}`)},
		{ID: 145, MetadataJSON: []byte(`{"ID":145,"Name":"a145"}`)},
		{ID: 244, MetadataJSON: []byte(`{"ID":244,"Name":"a244"}`)},
	}}
	settings := OpenAITicketGrabSettings{Enabled: true, AccountIDs: []int64{133}, AttachToForward: true, AttachAccountIDs: []int64{145}}
	dir := NewTicketGrabAwareAccountDirectory(base, &fakeTicketGrabSettingRepo{value: ticketGrabSettingsJSON(t, settings)})

	infos, err := dir.ListPluginAccounts(context.Background(), PluginAccountScope{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 3 {
		t.Fatalf("账号数量错误: %d", len(infos))
	}
	if !metadataHasTicketGrab(t, infos[0].MetadataJSON) {
		t.Error("133（打票 account_ids）应被标注 ticket_grab")
	}
	if !metadataHasTicketGrab(t, infos[1].MetadataJSON) {
		t.Error("145（attach 账号）应被标注 ticket_grab")
	}
	if metadataHasTicketGrab(t, infos[2].MetadataJSON) {
		t.Error("244 不应被标注 ticket_grab")
	}
	// 原有键保留。
	var obj map[string]any
	_ = json.Unmarshal(infos[2].MetadataJSON, &obj)
	if obj["Name"] != "a244" {
		t.Errorf("原 MetadataJSON 键被改动: %v", obj)
	}
}

// 打票总开关关闭时不标注任何账号。
func TestTicketGrabDirectoryDisabled(t *testing.T) {
	base := &fakeBaseDirectory{infos: []PluginAccountInfo{
		{ID: 133, MetadataJSON: []byte(`{"ID":133}`)},
	}}
	settings := OpenAITicketGrabSettings{Enabled: false, AccountIDs: []int64{133}}
	dir := NewTicketGrabAwareAccountDirectory(base, &fakeTicketGrabSettingRepo{value: ticketGrabSettingsJSON(t, settings)})

	infos, err := dir.ListPluginAccounts(context.Background(), PluginAccountScope{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if metadataHasTicketGrab(t, infos[0].MetadataJSON) {
		t.Error("打票关闭时不应标注")
	}
}

// 设置读取失败或为空时静默退化为无标注，绝不阻断目录列举。
func TestTicketGrabDirectorySettingsFailure(t *testing.T) {
	base := &fakeBaseDirectory{infos: []PluginAccountInfo{
		{ID: 133, MetadataJSON: []byte(`{"ID":133}`)},
		{ID: 200, MetadataJSON: nil},
	}}
	dir := NewTicketGrabAwareAccountDirectory(base, &fakeTicketGrabSettingRepo{err: errors.New("boom")})

	infos, err := dir.ListPluginAccounts(context.Background(), PluginAccountScope{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if metadataHasTicketGrab(t, infos[0].MetadataJSON) || metadataHasTicketGrab(t, infos[1].MetadataJSON) {
		t.Error("设置读取失败时不应标注")
	}
}

// MetadataJSON 为空/损坏时注入仍应产生仅含 ticket_grab 的对象（标记不丢失）。
func TestInjectTicketGrabFlagDegraded(t *testing.T) {
	out := injectTicketGrabFlag(nil)
	if !metadataHasTicketGrab(t, out) {
		t.Errorf("空 metadata 注入失败: %s", out)
	}
	out = injectTicketGrabFlag([]byte(`not-json`))
	if !metadataHasTicketGrab(t, out) {
		t.Errorf("损坏 metadata 注入失败: %s", out)
	}
}

// 凭据解析通道原样透传，不被装饰层改写。
func TestTicketGrabDirectoryResolvePassthrough(t *testing.T) {
	identity := &PluginOutboundIdentity{AccountID: 244, Token: "tok"}
	base := &fakeBaseDirectory{identity: identity}
	dir := NewTicketGrabAwareAccountDirectory(base, &fakeTicketGrabSettingRepo{value: `{"enabled":true,"account_ids":[244]}`})

	got, err := dir.ResolvePluginOutboundIdentity(context.Background(), PluginAccountScope{}, 244)
	if err != nil || got != identity || got.Token != "tok" {
		t.Fatalf("解析应原样透传: %+v %v", got, err)
	}
	if base.resolveID != 244 {
		t.Errorf("accountID 未透传: %d", base.resolveID)
	}
}
