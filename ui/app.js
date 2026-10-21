(function () {
  "use strict";

  var byId = function (id) { return document.getElementById(id); };
  var state = { ui: null, busy: false, reload: false, online: false, apps: [], selected: "", jobs: [], job: null, fingerprint: "", deviceTimer: null, jobTimer: null, uploading: false, cancelUpload: false };
  var terminal = new Set(["completed", "complete", "succeeded", "success", "done", "failed", "error", "stopped", "cancelled", "canceled", "interrupted"]);
  var buttonIds = ["device-connect", "device-refresh", "device-disconnect", "config-reload", "config-save", "device-probe", "fingerprint-use", "apps-refresh", "test-start", "dump-start", "hook-start", "proxy-start", "proxy-rules-save", "api-start", "job-refresh", "job-stop", "jobs-refresh", "artifacts-refresh", "package-upload"];
  var selectedButtons = ["test-start", "dump-start", "hook-start"];

  function text(id, value) { byId(id).textContent = value == null ? "—" : String(value); }
  function pretty(value) { return typeof value === "string" ? value : JSON.stringify(value, null, 2); }
  function notice(message, bad) { text("notice", message); byId("notice").setAttribute("role", bad ? "alert" : "status"); }
  function isFinished(job) { return job && terminal.has(String(job.status || "").toLowerCase()); }
  function updateControls() {
    var locked = !state.ui || state.busy || state.reload;
    buttonIds.forEach(function (id) { byId(id).disabled = locked; });
    selectedButtons.forEach(function (id) { byId(id).disabled = locked || !state.online || !state.selected; });
    byId("apps-refresh").disabled = locked || !state.online;
    byId("proxy-start").disabled = locked || !state.online;
    byId("device-disconnect").disabled = locked || !state.online;
    byId("fingerprint-use").disabled = locked || !state.fingerprint;
    byId("job-refresh").disabled = locked || !state.job;
    byId("job-stop").disabled = locked || !state.job || isFinished(state.job);
    byId("device-poll").disabled = locked || !state.online;
    byId("job-poll").disabled = locked || !state.job || isFinished(state.job);
    byId("proxy-rules-save").disabled = locked || !state.job || state.job.kind !== "proxy" || state.job.status !== "running" || state.job.stage !== "capturing";
    byId("package-cancel").disabled = !state.uploading || state.cancelUpload;
    byId("package-file").disabled = locked;
    document.querySelectorAll("[data-action]").forEach(function (button) { button.disabled = locked; });
  }
  async function action(label, fn) {
    if (!state.ui || state.busy || state.reload) return;
    state.busy = true;
    updateControls();
    notice(label + "…");
    try { await fn(); }
    catch (error) { notice(label + "失败：" + (error && error.message ? error.message : String(error)), true); }
    finally { state.busy = false; updateControls(); }
  }
  function onClick(id, label, fn) { byId(id).addEventListener("click", function () { return action(label, fn); }); }
  function decodeTool(result) {
    var payload = result;
    if (result && Array.isArray(result.content)) {
      var texts = result.content.filter(function (item) { return item && item.type === "text" && typeof item.text === "string"; });
      if (!texts.length) throw new Error("工具未返回文本结果");
      try { payload = JSON.parse(texts.map(function (item) { return item.text; }).join("\n")); }
      catch (_) { throw new Error(texts.map(function (item) { return item.text; }).join("\n").slice(0, 2000) || "工具结果不是合法 JSON"); }
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("工具结果格式不正确");
    var meta = result && (result._meta || result.meta);
    if (meta) payload._meta = meta;
    if (!payload.artifacts && meta && Array.isArray(meta.artifacts)) payload.artifacts = meta.artifacts;
    if ((result && result.isError) || payload.ok === false || (payload.error && !payload.job_id)) {
      throw new Error(typeof payload.error === "string" ? payload.error : pretty(payload.error || payload));
    }
    return payload;
  }
  async function tool(name, args) { return decodeTool(await state.ui.callTool(name, args || {})); }
  async function collectPages(name, field, limit, maxItems) {
    var items = [];
    var offset = 0;
    while (true) {
      var result = await tool(name, { offset: offset, limit: limit });
      if (!Array.isArray(result[field])) throw new Error(result.summary ? "列表被工具摘要截断：" + result.summary : "工具未返回 " + field + " 列表");
      items = items.concat(result[field]);
      if (items.length > maxItems) throw new Error("列表超过界面读取上限 " + maxItems + "，未覆盖原有列表");
      if (result.next_offset === null || result.next_offset === undefined) return items;
      if (!Number.isInteger(result.next_offset) || result.next_offset <= offset || !result[field].length || items.length >= maxItems) throw new Error("列表分页偏移异常，未覆盖原有列表");
      offset = result.next_offset;
    }
  }
  function integer(id, min, max) {
    var value = Number(byId(id).value);
    if (!Number.isInteger(value) || value < min || value > max) throw new Error("请输入 " + min + "–" + max + " 之间的整数");
    return value;
  }
  function requireApp() {
    if (!state.online) throw new Error("请先连接设备");
    if (!state.selected) throw new Error("请先选择应用");
    return state.selected;
  }
  function clearSecrets() { ["ssh-password", "ssh-private-key", "ssh-passphrase"].forEach(function (id) { byId(id).value = ""; }); }
  async function loadConfig() {
    var result = await state.ui.getConfig();
    var values = result && result.values ? result.values : (result || {});
    byId("ssh-host").value = values.SSH_HOST || "";
    byId("ssh-port").value = values.SSH_PORT || "22";
    byId("ssh-user").value = values.SSH_USER || "root";
    byId("ssh-fingerprint").value = values.SSH_FINGERPRINT || "";
    clearSecrets();
    var keys = state.ui.context && state.ui.context.configKeys || [];
    text("secret-state", "已配置的密钥项：" + (["SSH_PASSWORD", "SSH_PRIVATE_KEY", "SSH_KEY_PASSPHRASE"].filter(function (key) { return keys.indexOf(key) >= 0; }).join("、") || "无"));
    text("device-target", (values.SSH_USER || "root") + "@" + (values.SSH_HOST || "未设置") + ":" + (values.SSH_PORT || "22"));
    state.fingerprint = "";
    byId("probe-panel").hidden = true;
    notice("配置已读取。可手动连接设备；首次连接记录主机密钥，也可选填已核对的指纹。");
  }
  function stopDevicePoll() {
    if (state.deviceTimer !== null) clearInterval(state.deviceTimer);
    state.deviceTimer = null;
    byId("device-poll").checked = false;
  }
  function stopJobPoll() {
    if (state.jobTimer !== null) clearInterval(state.jobTimer);
    state.jobTimer = null;
    byId("job-poll").checked = false;
  }
  function renderDevice(data) {
    state.online = data.online === true || data.status === "online";
    text("device-online", state.online ? "在线" : "离线 / 未连接");
    text("device-status", state.online ? "设备在线" : "设备离线");
    byId("device-status").className = "pui-pill" + (state.online ? " ok" : " bad");
    text("device-time", new Date().toLocaleTimeString());
    text("device-info", pretty(data));
    if (!state.online) stopDevicePoll();
    updateControls();
  }
  function deviceFailure() {
    state.online = false;
    stopDevicePoll();
    text("device-online", "状态未知，检查失败");
    text("device-status", "设备状态未知");
    byId("device-status").className = "pui-pill bad";
  }
  async function refreshDevice() {
    try { renderDevice(await tool("ios_device_status", { refresh: true })); notice("设备状态已更新。"); }
    catch (error) { deviceFailure(); throw error; }
  }
  function startDevicePoll() {
    stopDevicePoll();
    if (!state.online) return;
    byId("device-poll").checked = true;
    state.deviceTimer = setInterval(function () { return action("刷新设备状态", refreshDevice); }, 10000);
  }
  function make(tag, className, value) {
    var element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = String(value);
    return element;
  }
  function button(label, fn) {
    var element = make("button", "pui-btn", label);
    element.type = "button";
    element.setAttribute("data-action", "true");
    element.disabled = state.busy || state.reload || !state.ui;
    element.addEventListener("click", fn);
    return element;
  }
  function emptyRow(body, columns, message) {
    var row = make("tr");
    var cell = make("td", "pui-empty", message);
    cell.colSpan = columns;
    row.appendChild(cell);
    body.appendChild(row);
  }
  function renderApps() {
    var body = byId("apps-body");
    body.replaceChildren();
    var filter = byId("apps-filter").value.trim().toLowerCase();
    var apps = state.apps.filter(function (app) { return (String(app.name || "") + " " + String(app.bundle_id || "")).toLowerCase().indexOf(filter) >= 0; });
    apps.forEach(function (app) {
      var row = make("tr");
      var pick = make("td");
      pick.appendChild(button(state.selected === app.bundle_id ? "已选择" : "选择", function () {
        state.selected = app.bundle_id;
        text("selected-app", (app.name || app.bundle_id) + " · " + app.bundle_id);
        renderApps();
        updateControls();
      }));
      row.appendChild(pick);
      row.appendChild(make("td", "", app.name || "—"));
      row.appendChild(make("td", "mono", app.bundle_id));
      body.appendChild(row);
    });
    if (!apps.length) emptyRow(body, 3, state.apps.length ? "没有匹配的应用" : "连接设备后，点击“读取应用”");
    text("apps-count", "显示 " + apps.length + " / " + state.apps.length + " 个应用");
  }
  function artifactObject(artifact) { return typeof artifact === "string" ? { path: artifact } : artifact; }
  function canPreview(artifact) { return /\.(?:json|jsonl|ndjson|txt|md|log|csv|html?|xml|ya?ml)$/i.test(artifact.path || "") && (!artifact.size || artifact.size <= 1048576); }
  async function previewArtifact(artifact) {
    if (!canPreview(artifact)) throw new Error("此产物不支持文本预览，请在宿主插件产物页下载");
    var result = await state.ui.readArtifact(artifact.path, "text");
    text("artifact-name", artifact.path);
    text("artifact-preview", typeof result === "string" ? result : result.data === undefined ? pretty(result) : result.data);
    notice("已读取报告原文：" + artifact.path);
  }
  function renderArtifacts(id, artifacts, emptyText) {
    var list = byId(id);
    list.replaceChildren();
    (artifacts || []).map(artifactObject).filter(function (item) { return item && typeof item.path === "string"; }).forEach(function (artifact) {
      var item = make("li");
      item.appendChild(make("span", "", artifact.path + (artifact.size ? " · " + artifact.size + " B" : "")));
      if (canPreview(artifact)) item.appendChild(button("预览原文", function () { return action("读取报告", function () { return previewArtifact(artifact); }); }));
      else item.appendChild(make("span", "pui-hint", "请到宿主产物页下载"));
      list.appendChild(item);
    });
    if (!list.children.length) list.appendChild(make("li", "pui-empty", emptyText));
  }
  function renderJobs() {
    var body = byId("jobs-body");
    body.replaceChildren();
    state.jobs.forEach(function (job) {
      var row = make("tr");
      row.appendChild(make("td", "mono", job.job_id));
      row.appendChild(make("td", "", [job.type || job.kind || job.mode, job.bundle_id].filter(Boolean).join(" / ") || "—"));
      row.appendChild(make("td", "", [job.status, job.stage].filter(Boolean).join(" / ")));
      var cell = make("td");
      cell.appendChild(button("查看", function () { return action("读取任务", async function () { stopJobPoll(); state.job = job; renderJob(job); await refreshJob(); }); }));
      row.appendChild(cell);
      body.appendChild(row);
    });
    if (!state.jobs.length) emptyRow(body, 4, "点击“读取任务列表”，或手动启动一项任务");
  }
  function renderJob(job) {
    state.job = job;
    var index = state.jobs.findIndex(function (item) { return item.job_id === job.job_id; });
    if (index < 0) state.jobs.unshift(job); else state.jobs[index] = job;
    text("job-id", job.job_id);
    text("job-stage", job.stage || "等待更新");
    text("job-state", job.status || "未知");
    byId("job-state").className = "pui-pill" + (job.error || /failed|error/.test(job.status) ? " bad" : isFinished(job) ? " ok" : "");
    text("job-detail", pretty(job));
    renderArtifacts("job-artifacts", job.artifacts || [], "此任务暂无产物");
    if (isFinished(job)) { stopJobPoll(); text("job-hint", "任务已结束，轮询已停止。可预览任务产物或读取其他任务。"); }
    else text("job-hint", "可手动刷新，或显式开启每 3 秒轮询。关闭轮询不会停止后台任务。");
    renderJobs();
    updateControls();
  }
  async function refreshJob() {
    if (!state.job) throw new Error("请先选择任务");
    try { renderJob(await tool("ios_job_status", { job_id: state.job.job_id })); notice("任务状态已更新。"); }
    catch (error) { stopJobPoll(); throw error; }
  }
  async function startJob(name, args) {
    var job = await tool(name, args);
    if (!job.job_id) throw new Error("工具未返回任务 ID：" + pretty(job));
    stopJobPoll();
    renderJob(job);
    notice("任务已提交：" + job.job_id + "。可手动刷新或开启任务轮询。");
  }
  function headers(id) {
    var value;
    try { value = JSON.parse(byId(id).value || "{}"); } catch (_) { throw new Error("请求头必须是合法 JSON"); }
    return validateHeaders(value);
  }
  function validateHeaders(value) {
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.values(value).some(function (item) { return typeof item !== "string"; })) throw new Error("请求头必须是键值均为字符串的 JSON 对象");
    if (Object.keys(value).length > 60) throw new Error("请求头最多 60 项");
    Object.keys(value).forEach(function (key) { if (Array.from(value[key]).length > 8192 || /[\r\n]/.test(key + value[key])) throw new Error("请求头值最多 8192 字符，键和值均不能包含换行"); });
    return value;
  }

  onClick("config-reload", "读取配置", loadConfig);
  onClick("config-save", "保存配置", async function () {
    var host = byId("ssh-host").value.trim();
    var user = byId("ssh-user").value.trim();
    if (!host || !user) throw new Error("设备地址和 SSH 用户不能为空");
    var values = { SSH_HOST: host, SSH_PORT: String(integer("ssh-port", 1, 65535)), SSH_USER: user, SSH_FINGERPRINT: byId("ssh-fingerprint").value.trim() };
    [["ssh-password", "SSH_PASSWORD"], ["ssh-private-key", "SSH_PRIVATE_KEY"], ["ssh-passphrase", "SSH_KEY_PASSPHRASE"]].forEach(function (pair) { if (byId(pair[0]).value.trim()) values[pair[1]] = byId(pair[0]).value; });
    stopDevicePoll();
    stopJobPoll();
    clearSecrets();
    state.reload = true;
    try {
      await state.ui.saveConfig(values);
      notice("配置已保存，插件容器正在重建。请使用宿主“重载”重新打开界面，再手动连接设备。");
    } catch (error) {
      throw new Error("保存结果未确认（" + (error.message || error) + "）。容器可能已重建，请使用宿主“重载”后重新读取配置核实。");
    }
  });
  onClick("device-probe", "读取 SSH 指纹", async function () {
    var result = await tool("ios_device_probe", {});
    state.fingerprint = typeof result.fingerprint === "string" ? result.fingerprint : "";
    text("probe-result", pretty(result));
    byId("probe-panel").hidden = false;
    notice("已读取已保存地址的指纹。可选：通过可信渠道核对后填入并保存；也可直接手动连接并记录首次主机密钥。");
  });
  onClick("fingerprint-use", "填入已确认指纹", async function () { byId("ssh-fingerprint").value = state.fingerprint; notice("已填入确认的指纹；请保存配置并重载界面后连接。"); });
  onClick("device-connect", "连接设备", async function () {
    stopDevicePoll();
    try {
      var data = await tool("ios_device_connect", {});
      renderDevice(data);
      if (state.online) { startDevicePoll(); notice("设备已连接，状态每 10 秒更新；可取消勾选暂停刷新。"); }
      else notice("设备未连接，请查看系统信息与能力详情。", true);
    } catch (error) { deviceFailure(); throw error; }
  });
  onClick("device-refresh", "刷新设备状态", refreshDevice);
  onClick("device-disconnect", "断开设备", async function () {
    stopDevicePoll();
    try { renderDevice(await tool("ios_device_disconnect", {})); notice("设备已断开。后台任务请在任务区确认状态或停止。"); }
    catch (error) { deviceFailure(); throw error; }
  });
  byId("device-poll").addEventListener("change", function () {
    if (byId("device-poll").checked && state.online) { startDevicePoll(); notice("已开启每 10 秒状态刷新。"); }
    else { stopDevicePoll(); notice("已暂停设备状态刷新，设备连接未因此断开。"); }
  });
  onClick("apps-refresh", "读取应用列表", async function () {
    var apps = await collectPages("ios_apps_list", "apps", 100, 2000);
    state.apps = apps.filter(function (app) { return app && typeof app.bundle_id === "string"; });
    if (!state.apps.some(function (app) { return app.bundle_id === state.selected; })) { state.selected = ""; text("selected-app", "尚未选择"); }
    renderApps();
    notice("应用列表已更新，请选择目标应用。");
  });
  byId("apps-filter").addEventListener("input", renderApps);
  onClick("test-start", "启动客户端分析", function () { return startJob("ios_test_start", { bundle_id: requireApp(), mode: byId("test-mode").value, duration: integer("test-duration", 5, 600) }); });
  byId("hook-replace").addEventListener("change", function () { byId("hook-replace-fields").hidden = !byId("hook-replace").checked; });
  onClick("hook-start", "启动 Hook 观察", function () {
    var args = { bundle_id: requireApp(), duration: integer("test-duration", 5, 600), profile: byId("hook-profile").value };
    if (byId("hook-replace").checked) {
      if (args.profile !== "crypto") throw new Error("文本替换仅支持 crypto 观察范围");
      var from = byId("hook-from").value;
      var to = byId("hook-to").value;
      if (Array.from(from).length > 512 || Array.from(to).length > 512) throw new Error("替换文本最多 512 个字符");
      if (!from || !to || new TextEncoder().encode(from).length !== new TextEncoder().encode(to).length) throw new Error("替换文本必须非空且 UTF-8 字节长度相等");
      args.replace_from = from;
      args.replace_to = to;
    }
    return startJob("ios_hook_start", args);
  });
  onClick("dump-start", "导出应用包", function () { return startJob("ios_dump_start", { bundle_id: requireApp() }); });
  onClick("proxy-start", "启动代理", function () { return startJob("ios_proxy_start", { duration: integer("proxy-duration", 5, 600), reverse: true }); });
  onClick("proxy-rules-save", "应用代理规则", async function () {
    var rules;
    try { rules = JSON.parse(byId("proxy-rules").value); } catch (_) { throw new Error("代理规则必须是合法 JSON 数组"); }
    if (!Array.isArray(rules) || rules.some(function (rule) { return !rule || typeof rule !== "object" || Array.isArray(rule); })) throw new Error("代理规则必须是对象组成的数组");
    if (rules.length > 20) throw new Error("代理规则最多 20 条");
    rules.forEach(function (rule) {
      if (typeof rule.url_contains !== "string" || Array.from(rule.url_contains).length < 8 || Array.from(rule.url_contains).length > 2048) throw new Error("每条代理规则的 url_contains 必须为 8–2048 字符");
      if (Object.keys(rule).some(function (key) { return ["url_contains", "request_headers", "request_body", "response_body"].indexOf(key) < 0; })) throw new Error("代理规则包含不支持的字段");
      ["request_body", "response_body"].forEach(function (key) { if (key in rule && (typeof rule[key] !== "string" || Array.from(rule[key]).length > 65536)) throw new Error(key + " 必须是最多 65536 字符的文本"); });
      if (rule.request_headers !== undefined) validateHeaders(rule.request_headers);
    });
    var result = await tool("ios_proxy_rules_set", { job_id: state.job.job_id, rules: rules });
    text("job-detail", pretty(result));
    notice("代理规则已提交，请以工具结果确认生效范围。");
  });
  function readChunk(blob) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result).split(",")[1]); };
      reader.onerror = function () { reject(new Error("读取本地文件失败")); };
      reader.onabort = function () { reject(new Error("读取本地文件已取消")); };
      reader.readAsDataURL(blob);
    });
  }
  byId("package-cancel").addEventListener("click", function () {
    state.cancelUpload = true;
    byId("package-cancel").disabled = true;
    text("package-progress", "正在取消上传；当前分片返回后停止，不会创建分析任务。");
  });
  onClick("package-upload", "上传应用包", async function () {
    var file = byId("package-file").files && byId("package-file").files[0];
    if (!file || !/\.(ipa|zip)$/i.test(file.name)) throw new Error("请选择 .ipa 或 .zip 文件");
    var filename = file.name.replace(/\.(ipa|zip)$/i, function (suffix) { return suffix.toLowerCase(); });
    if (/[\\/]/.test(filename) || !filename.slice(0, -4) || Array.from(filename.slice(0, -4)).length > 150) throw new Error("文件名不能含路径，且扩展名前需 1–150 个字符");
    if (!file.size || file.size > 536870912) throw new Error("文件必须非空且不超过 512 MB");
    state.uploading = true;
    state.cancelUpload = false;
    updateControls();
    var uploadId = null;
    var finished = false;
    try {
      var upload = await tool("ios_package_import_start", { filename: filename, size: file.size });
      if (!upload.upload_id) throw new Error("工具未返回上传 ID");
      uploadId = upload.upload_id;
      var offset = 0;
      while (offset < file.size) {
        if (state.cancelUpload) { text("package-progress", "上传已取消，未创建分析任务。"); notice("上传已取消。"); return; }
        var end = Math.min(offset + 262144, file.size);
        var encoded = await readChunk(file.slice(offset, end));
        if (state.cancelUpload) { text("package-progress", "上传已取消，未创建分析任务。"); notice("上传已取消。"); return; }
        var part = await tool("ios_package_import_chunk", { upload_id: upload.upload_id, offset: offset, data_base64: encoded });
        if (part.offset !== end) throw new Error("分片确认偏移不一致，上传已停止");
        offset = end;
        text("package-progress", "已上传 " + offset + " / " + file.size + " B（" + Math.floor(offset * 100 / file.size) + "%）");
      }
      if (state.cancelUpload) { text("package-progress", "上传已取消，未创建分析任务。"); notice("上传已取消。"); return; }
      // Finalization creates a task; cancellation applies only before this call.
      state.uploading = false;
      updateControls();
      await startJob("ios_package_import_finish", { upload_id: upload.upload_id });
      finished = true;
      text("package-progress", "上传完成，已创建静态分析任务。SHA-256 与分析结果请查看任务详情。");
      byId("package-file").value = "";
    } catch (error) { text("package-progress", "上传或分析提交失败：" + (error.message || error)); throw error; }
    finally {
      if (uploadId && !finished) {
        try { await tool("ios_package_import_cancel", { upload_id: uploadId }); }
        catch (_) { text("package-progress", byId("package-progress").textContent + " 服务器临时文件清理未确认；完成状态不明时请读取任务列表核实。"); }
      }
      state.uploading = false;
      state.cancelUpload = false;
    }
  });
  onClick("api-start", "执行接口对照", function () {
    var url;
    try { url = new URL(byId("api-url").value.trim()); } catch (_) { throw new Error("请输入完整的 HTTP(S) 接口地址"); }
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.href.length > 8192) throw new Error("接口地址仅支持不含用户信息的 HTTP(S) URL，最长 8192 字符");
    var method = byId("api-method").value;
    if (["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].indexOf(method) < 0) throw new Error("请选择支持的 HTTP 请求方法");
    var body = byId("api-body").value;
    if (Array.from(body).length > 65536) throw new Error("请求正文最多 65536 个字符");
    var args = { url: url.href, method: method, base_headers: headers("api-base-headers"), headers: headers("api-headers"), compare_headers: headers("api-compare") };
    if (body !== "") args.body = body;
    return startJob("ios_api_check", args);
  });
  onClick("job-refresh", "刷新任务", refreshJob);
  onClick("job-stop", "停止任务", async function () {
    var result = await tool("ios_job_stop", { job_id: state.job.job_id });
    renderJob(result);
    notice("已请求停止任务，请以当前状态确认停止完成。");
  });
  byId("job-poll").addEventListener("change", function () {
    if (!byId("job-poll").checked || !state.job || isFinished(state.job)) { stopJobPoll(); notice("已暂停任务轮询，后台任务未因此停止。"); return; }
    stopJobPoll();
    byId("job-poll").checked = true;
    state.jobTimer = setInterval(function () { return action("刷新任务", refreshJob); }, 3000);
    notice("已开启每 3 秒任务轮询，结束或读取失败后自动停止。");
  });
  onClick("jobs-refresh", "读取任务列表", async function () {
    var jobs = await collectPages("ios_jobs_list", "jobs", 20, 100);
    state.jobs = jobs.filter(function (job) { return job && job.job_id; });
    renderJobs();
    notice("任务列表已更新。");
  });
  onClick("artifacts-refresh", "读取产物列表", async function () {
    var result = await state.ui.listArtifacts();
    renderArtifacts("artifacts-list", Array.isArray(result) ? result : result.artifacts || [], "暂无产物");
    notice("产物列表已更新。");
  });
  window.addEventListener("pagehide", function () { stopDevicePoll(); stopJobPoll(); clearSecrets(); });
  renderApps();
  renderJobs();
  renderArtifacts("artifacts-list", [], "点击“读取产物列表”查看已有报告");
  (async function () {
    try { state.ui = await SentinelPlugin.connect(); await action("读取配置", loadConfig); }
    catch (error) { notice("界面连接失败：" + (error.message || error) + "。请使用宿主“重载”重试。", true); }
    updateControls();
  })();
})();
