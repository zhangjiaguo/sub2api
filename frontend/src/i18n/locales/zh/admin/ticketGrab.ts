export default {
  ticketGrab: {
    title: 'Codex 打票',
    description: '通过动态代理出口为账号采集 Codex turn-state 票据',

    // 设置卡片
    settings: '打票设置',
    enabled: '启用打票',
    enabledHelp: '启用后按调度规则自动补票',
    proxyUrl: '动态代理地址',
    proxyUrlHelp: '支持 http / https / socks5 / socks5h，凭证内嵌在地址中；动态代理按连接轮换出口 IP',
    testProxy: '测试代理',
    testing: '测试中...',
    testResult: '代理测试结果（3 次独立连接采样）',
    model: '探测模型',
    leadSeconds: '提前打票秒数',
    leadSecondsHelp: '票据剩余有效期低于该值时触发补票',
    ttlSeconds: '票据有效期（秒）',
    ttlSecondsHelp: '按上游实测为 1 小时',
    minInterval: '打票最小间隔（秒）',
    minIntervalHelp: '同一账号两次打票之间的最小间隔（频率上限）',
    probeTimeout: '单次探测超时（秒）',
    expectedLength: '期望票据长度（字符）',
    expectedLengthHelp: '符合期望才算有效票（gpt-6-astra 实测 780）',
    expectedBlocks: '期望块数',
    maxProbes: '每轮最多探测次数',
    maxProbesHelp: '每次探测使用新的代理出口；429/401/403 不会重试换出口',
    save: '保存设置',
    saving: '保存中...',

    // 账号选择
    accounts: '打票账号',
    accountsHelp: '从分组中选择参与打票的 OpenAI OAuth 账号',
    selectGroup: '选择分组',
    allGroups: '全部分组',
    selectedCount: '已选 {count} 个账号',

    // 状态表
    status: '打票状态',
    account: '账号',
    ticketLength: '票据长度/块',
    validUntil: '剩余有效期',
    exitIp: '出口 IP',
    lastGrab: '上次打票',
    successRate: '成功率',
    validRate: '有效率',
    validRateHelp: '有效率 = 符合期望长度/块数的打票占比（24 小时窗口）',
    actions: '操作',
    runNow: '立即打票',
    running: '打票中...',
    noTicket: '暂无票据',
    expired: '已过期',
    nextRun: '下次',
    cooldown: '冷却中',
    noAccountsSelected: '尚未选择打票账号',

    // 日志
    logs: '打票日志',
    time: '时间',
    result: '结果',
    duration: '耗时',
    detail: '详情',
    allAccounts: '全部账号',
    refresh: '刷新',

    // 结果码
    resultCodes: {
      accepted: '成功',
      shape_mismatch: '形态不符',
      state_invalid: '票据非法',
      missing_state: '缺少票据',
      incomplete: '流未完成',
      http_429: '限流 429',
      http_401: '未授权 401',
      http_403: '拒绝 403',
      network_error: '网络错误',
      token_error: '令牌错误',
      request_error: '请求错误',
      no_token_provider: '缺少令牌提供器'
    }
  }
}
