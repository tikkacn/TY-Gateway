(() => {
  const nav = document.querySelector('.nav');
  const content = document.querySelector('.content');
  if (!nav || !content) return;
  pageNames.enrollments = '设备准入';

  const button = document.createElement('button');
  button.className = 'nav-btn';
  button.dataset.page = 'enrollments';
  button.innerHTML = '<span class="nav-icon">⊞</span>设备准入';
  nav.insertBefore(button, nav.querySelector('[data-page="subscriptions"]'));

  const page = document.createElement('section');
  page.id = 'page-enrollments';
  page.className = 'page';
  page.innerHTML = `
    <div class="page-head"><div><div class="eyebrow">Device enrollment</div><h1>设备准入</h1>
      <p>先预登记设备 MAC。安装通用软件包后，设备联网会自动认领并注册专属身份。</p></div>
      <div class="head-actions"><button id="enrollmentRefresh" class="btn secondary">↻ 刷新</button></div></div>
    <div class="grid-2" style="margin-top:0">
      <section class="panel"><div class="panel-head"><div><h2>预登记设备</h2><p>只登记 MAC、备注和设备策略；无需生成或传输逐台激活文件。</p></div></div>
        <div class="panel-body"><form id="enrollmentForm" class="form-grid">
          <label class="field"><span class="field-label">设备 MAC</span><input id="enrollmentMAC" required maxlength="32" placeholder="例如 AA:BB:CC:DD:EE:FF" autocomplete="off"></label>
          <label class="field"><span class="field-label">管理员备注</span><input id="enrollmentNote" maxlength="255" placeholder="例如 客户代号 / 安装地点"></label>
          <label class="field"><span class="field-label">规则方案</span><select id="enrollmentProfile"><option value="gfw_precise">GFW 精准代理</option></select></label>
          <label class="field"><span class="field-label">预绑定订阅（可选）</span><select id="enrollmentSubscription"><option value="">暂不绑定</option></select></label>
          <div class="field full"><button class="btn" type="submit">保存 MAC 预登记</button></div>
        </form></div></section>
      <section class="panel"><div class="panel-head"><div><h2>安装顺序</h2><p>所有新设备共用同一份不含逐台凭据的安装包。</p></div></div>
        <div class="panel-body"><p>1. 在后台登记设备有线网卡 MAC、备注和需要绑定的策略。</p>
          <p>2. 在设备上运行通用安装包；Agent 首次联网时会先在本机安全保存随机身份密钥，再向云端认领。</p>
          <p>3. 云端只接受已预登记且尚未认领的 MAC，并把该 MAC 原子绑定到首次成功的设备身份；成功后自动下发该设备的策略和订阅。</p>
          <p class="muted">MAC 不是密码，首次认领存在 MAC 仿冒/抢先认领风险；后台应只登记已售出设备的 MAC。自动 FRP 只会连接独立 per-device 监听，不会接触现有 7001/22000 救援通道。DHCP、DNS 和 DAE 代理开关仍按设备当前配置执行，不会因注册而自动打开。</p>
        </div></section>
    </div>
    <section class="panel" style="margin-top:18px"><div class="panel-head"><div><h2>预登记列表</h2><p>过期或未使用的记录可撤销后重新生成。</p></div></div>
      <div class="table-wrap"><table><thead><tr><th>MAC / 备注</th><th>规则与订阅</th><th>有效期</th><th>状态</th><th></th></tr></thead>
        <tbody id="enrollmentRows"></tbody></table></div></section>`;
  content.append(page);

  const renderOptions = (packages) => {
    const profile = document.getElementById('enrollmentProfile');
    const selected = profile.value;
    profile.innerHTML = '<option value="gfw_precise">GFW 精准代理</option>';
    for (const item of packages || []) {
      const option = document.createElement('option');
      option.value = item.id;
      option.textContent = item.name + (item.available ? '' : '（尚未就绪）');
      option.disabled = !item.available;
      profile.append(option);
    }
    if ([...profile.options].some(item => item.value === selected)) profile.value = selected;
    const subscriptions = document.getElementById('enrollmentSubscription');
    const wanted = subscriptions.value;
    const reserved = new Set((state.enrollments || []).filter(item => !item.claimed_at).map(item => item.subscription_id));
    subscriptions.innerHTML = '<option value="">暂不绑定</option>';
    for (const item of state.subscriptions) {
      if (reserved.has(item.id) || state.devices.some(device => device.subscription_id === item.id)) continue;
      const option = document.createElement('option');
      option.value = item.id;
      option.textContent = item.name;
      subscriptions.append(option);
    }
    if ([...subscriptions.options].some(item => item.value === wanted)) subscriptions.value = wanted;
  };
  const renderRows = () => {
    const items = state.enrollments || [];
    document.getElementById('enrollmentRows').innerHTML = items.length ? items.map(item => {
      const status = item.claimed_at ? '已激活' : new Date(item.expires_at) <= new Date() ? '已过期' : '待激活';
      const subscription = state.subscriptions.find(sub => sub.id === item.subscription_id);
      return `<tr><td><div class="primary-cell"><strong class="mono">${esc(item.mac)}</strong><span>${esc(item.note || '无备注')}</span></div></td>
        <td>${esc(item.profile || 'gfw_precise')}<div class="muted">${esc(subscription?.name || '未绑定订阅')}</div></td>
        <td>${esc(fmtTime(item.expires_at))}</td><td><span class="badge ${item.claimed_at ? 'green' : status === '已过期' ? 'red' : 'amber'}">${status}</span></td>
        <td>${item.claimed_at ? '' : `<button class="btn secondary small" data-revoke-enrollment="${esc(item.mac)}">撤销</button>`}</td></tr>`;
    }).join('') : '<tr><td colspan="5" class="muted">尚无预登记设备</td></tr>';
  };
  async function loadEnrollments() {
    if (document.getElementById('app').classList.contains('hidden')) return;
    try {
      const [data, packages] = await Promise.all([api('/admin/enrollments'), api('/admin/rule-packages')]);
      state.enrollments = data.enrollments || [];
      renderOptions(packages.packages);
      renderRows();
    } catch (error) { toast('设备准入加载失败', error.message, true); }
  }
  const previousLoadState = loadState;
  loadState = async function (...args) {
    await previousLoadState(...args);
    if (page.classList.contains('active')) await loadEnrollments();
  };
  const previousEnterApp = enterApp;
  enterApp = function () {
    previousEnterApp();
    if (location.hash === '#enrollments') navigate('enrollments');
  };
  button.addEventListener('click', () => { navigate('enrollments'); loadEnrollments(); });
  document.getElementById('enrollmentRefresh').addEventListener('click', loadEnrollments);
  document.getElementById('enrollmentForm').addEventListener('submit', async event => {
    event.preventDefault();
    const submit = event.submitter;
    if (submit) submit.disabled = true;
    try {
      const body = {mac: document.getElementById('enrollmentMAC').value.trim(), note: document.getElementById('enrollmentNote').value.trim(), profile: document.getElementById('enrollmentProfile').value, subscription_id: document.getElementById('enrollmentSubscription').value};
      const result = await api('/admin/enrollments', {method:'POST', body:JSON.stringify(body)});
      await loadEnrollments();
      toast('MAC 预登记成功', '设备联网后会自动认领；确认登记的是设备实际使用的有线 MAC');
    } catch (error) { toast('预登记失败', error.message, true); }
    finally { if (submit) submit.disabled = false; }
  });
  document.getElementById('enrollmentRows').addEventListener('click', async event => {
    const revoke = event.target.closest('[data-revoke-enrollment]');
    if (!revoke || !confirm('撤销该 MAC 的待认领资格？已认领设备不会受影响。')) return;
    revoke.disabled = true;
    try {
      await api('/admin/enrollments/revoke', {method:'POST', body:JSON.stringify({mac:revoke.dataset.revokeEnrollment})});
      await loadEnrollments();
      toast('已撤销', '该 MAC 不再允许首次认领');
    } catch (error) { toast('撤销失败', error.message, true); revoke.disabled = false; }
  });
  if (location.hash === '#enrollments' && !document.getElementById('app').classList.contains('hidden')) {
    navigate('enrollments');
    loadEnrollments();
  }
})();
