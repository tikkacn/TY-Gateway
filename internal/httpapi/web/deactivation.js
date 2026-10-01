(() => {
  const previousOpenDrawer = openDrawer;
  openDrawer = function (id) {
    previousOpenDrawer(id);
    const device = state.selectedDevice;
    const body = document.getElementById('drawerBody');
    if (!device || device.id !== id || !body) return;
    const section = document.createElement('div');
    section.className = 'drawer-section';
    const title = document.createElement('h3');
    title.textContent = '设备反激活 · 重新安装前使用';
    const note = document.createElement('p');
    note.className = 'muted';
    note.style.cssText = 'font-size:12px;margin:0 0 12px;line-height:1.7';
    note.textContent = '撤销旧身份并移除设备中心记录、用户名称/邮箱、该设备的云端规则、节点偏好和命令，释放 FRP 登记。保留 MAC 准入、当前方案、订阅预绑定和管理员备注，恢复为待激活（30天）。不擦除本机系统或本地设置，不重排其他设备编号。旧程序不会自行再次激活；请重新刷机安装生成新身份。若只是暂停设备，请使用“禁用”；若只是修复分流，请重置客户规则。';
    const field = document.createElement('label');
    field.className = 'field';
    const label = document.createElement('span');
    label.className = 'field-label';
    label.textContent = '输入该设备 MAC 确认：' + device.serial;
    const input = document.createElement('input');
    input.placeholder = device.mac || device.serial;
    input.autocomplete = 'off';
    input.maxLength = 17;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn secondary small';
    button.textContent = '反激活此设备';
    button.disabled = true;
    const matches = () => /^[0-9a-fA-F:-]{12,17}$/.test(input.value.trim()) &&
      input.value.trim().replace(/[:-]/g, '').toUpperCase() === device.serial;
    input.addEventListener('input', () => { button.disabled = !matches(); });
    button.addEventListener('click', async () => {
      if (!matches() || state.selectedDevice?.id !== id ||
          !confirm('确定反激活 ' + device.serial + '？旧凭据和远程入口将失效。重新刷机安装后才可生成新身份认领，此操作不能用“启用”撤销。')) return;
      button.disabled = true;
      let committed = false;
      try {
        const response = await api('/admin/devices/deactivate', {
          method: 'POST', body: JSON.stringify({device_id: id, expected_version: device.config_version,
            mac: input.value.trim(), confirm: 'DEACTIVATE_DEVICE'})
        });
        committed = true;
        closeDrawer();
        toast('设备已反激活', response.message || 'MAC 已恢复待激活；FRP 授权撤销等待服务端同步。');
        await loadState(true);
      } catch (error) {
        toast(committed ? '反激活已完成，列表刷新失败' : '反激活未确认', error.message, true);
      } finally {
        if (!committed && section.isConnected) button.disabled = !matches();
      }
    });
    field.append(label, input);
    const actions = document.createElement('div');
    actions.className = 'drawer-actions';
    actions.append(button);
    section.append(title, note, field, actions);
    body.append(section);
  };
})();
