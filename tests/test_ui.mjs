import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import vm from "node:vm";

// A deliberately small DOM + host bridge. These tests execute the shipped SDK
// and app, dispatch real registered handlers, and inspect the resulting DOM and
// postMessage requests. They are not browser rendering or live-device tests.
const root = new URL("../", import.meta.url);
const html = await readFile(new URL("ui/index.html", root), "utf8");
const sdk = await readFile(new URL("ui/sdk.js", root), "utf8");
const app = await readFile(new URL("ui/app.js", root), "utf8");
const css = await readFile(new URL("ui/app.css", root), "utf8");
// Official v2.1.6 template digests; the source package can run these checks
// without a sibling checkout of Sentinel itself.
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
assert.equal(sha256(sdk), "60523de6381d7332680df2a8e5a1fcaab68d914cda88b5c77a88c556cc614509", "official SDK remains byte-identical");
assert.equal(sha256(await readFile(new URL("ui/base.css", root))), "432e2f716e1de85d220bddf1dca82884d245c014402c271fc6b7408d64f0dd85", "official base.css remains byte-identical");
assert.doesNotMatch(app, /\bfetch\s*\(|\bXMLHttpRequest\b|\blocalStorage\b|\bsessionStorage\b|\.cookie\b|\bhostAPI\b|\.storage\b|\binnerHTML\b/);
assert.doesNotMatch(css, /(?:^|[;{])\s*(?:font(?:-[\w-]+)?|color|background(?:-[\w-]+)?)\s*:/m, "page CSS only controls layout");
assert.doesNotMatch(html, /<h1\b/i, "the host owns the title");
assert.match(css, /overflow-x:\s*auto/);

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.attributes = {}; this.childNodes = [];
    this.listeners = new Map(); this._text = ""; this._value = undefined;
    this.disabled = false; this.checked = false; this.hidden = false; this.files = [];
  }
  get children() { return this.childNodes; }
  set textContent(value) { this._text = String(value); this.childNodes = []; }
  get textContent() { return this._text + this.childNodes.map((node) => node.textContent).join(""); }
  set innerHTML(_) { throw new Error("Dynamic HTML is forbidden"); }
  get innerHTML() { throw new Error("Dynamic HTML is forbidden"); }
  set value(value) { this._value = String(value); }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.tagName === "TEXTAREA") return this.textContent;
    if (this.tagName === "SELECT") return this.children[0]?.value || "";
    return "";
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name === "value") this.value = value;
    if (name === "id") this.id = value;
    if (name === "class") this.className = value;
    if (name === "type") this.type = value;
    if (["disabled", "checked", "hidden"].includes(name)) this[name] = true;
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  appendChild(element) { this.childNodes.push(element); return element; }
  replaceChildren(...elements) { this._text = ""; this.childNodes = elements; }
  addEventListener(name, listener) { this.listeners.set(name, [...this.listeners.get(name) || [], listener]); }
  async dispatch(name) {
    if (name === "click" && this.disabled) return;
    await Promise.all((this.listeners.get(name) || []).map((listener) => listener({ target: this, preventDefault() {} })));
  }
}

function documentFromHtml(source) {
  const document = new Element("document");
  const stack = [document];
  const voidTags = new Set(["meta", "link", "input", "br", "hr", "img"]);
  for (const token of source.match(/<!--[\s\S]*?-->|<![^>]*>|<[^>]+>|[^<]+/g)) {
    if (token.startsWith("<!")) continue;
    if (token.startsWith("</")) { stack.pop(); continue; }
    if (token.startsWith("<")) {
      const tag = token.match(/^<([\w-]+)/)?.[1];
      if (!tag) continue;
      const element = new Element(tag);
      const attributes = token.slice(tag.length + 1).replace(/\/?\s*>$/, "");
      for (const match of attributes.matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+)))?/g)) element.setAttribute(match[1], match[2] ?? match[3] ?? match[4] ?? "");
      stack.at(-1).appendChild(element);
      if (!voidTags.has(tag) && !token.endsWith("/>")) stack.push(element);
    } else stack.at(-1)._text += token.replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">");
  }
  const walk = (node) => [node, ...node.children.flatMap(walk)];
  document.getElementById = (id) => walk(document).find((node) => node.id === id) || null;
  document.querySelectorAll = (selector) => {
    assert.equal(selector, "[data-action]");
    return walk(document).filter((node) => node.getAttribute("data-action") !== null);
  };
  document.createElement = (tag) => new Element(tag);
  return document;
}

const json = (value) => JSON.parse(JSON.stringify(value));
const response = (data, extra = {}) => ({ content: [{ type: "text", text: JSON.stringify(data) }], ...extra });
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((resolve) => setImmediate(resolve)); };

async function harness({ config = {}, configKeys = [], handlers = {}, saveError = null } = {}) {
  const document = documentFromHtml(html);
  const events = new Map();
  const timers = new Map();
  const calls = [];
  let sequence = 0;
  const window = {
    location: { hash: "#nonce=ui-test" },
    addEventListener(name, fn) { events.set(name, [...events.get(name) || [], fn]); },
  };
  const dispatch = (name, value) => { for (const fn of events.get(name) || []) fn(value); };
  const parent = {
    postMessage(message) {
      if (message.kind === "sentinel-ui:hello") {
        queueMicrotask(() => dispatch("message", { source: parent, data: { kind: "sentinel-ui:init", context: { configKeys, tools: [] } } }));
        return;
      }
      calls.push(json(message));
      queueMicrotask(async () => {
        try {
          let result;
          if (message.method === "config.get") result = config;
          else if (message.method === "config.save") { if (saveError) throw new Error(saveError); result = { ok: true }; }
          else if (message.method === "tool.call") {
            const { name, arguments: args } = message.params;
            if (!handlers[name]) throw new Error("Unexpected tool call: " + name);
            result = await handlers[name](json(args));
          } else if (handlers[message.method]) result = await handlers[message.method](json(message.params));
          else throw new Error("Unexpected bridge call: " + message.method);
          dispatch("message", { source: parent, data: { kind: "sentinel-ui:result", id: message.id, ok: true, result } });
        } catch (error) {
          dispatch("message", { source: parent, data: { kind: "sentinel-ui:result", id: message.id, ok: false, error: error.message } });
        }
      });
    },
  };
  window.parent = parent;
  class FileReader {
    readAsDataURL(blob) {
      blob.arrayBuffer().then((buffer) => { this.result = "data:application/octet-stream;base64," + Buffer.from(buffer).toString("base64"); this.onload(); }).catch(() => this.onerror());
    }
  }
  const context = vm.createContext({
    window, document, URL, TextEncoder, FileReader, console,
    setTimeout(fn, ms) { const id = ++sequence; timers.set(id, { fn, ms, repeat: false }); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(fn, ms) { const id = ++sequence; timers.set(id, { fn, ms, repeat: true }); return id; },
    clearInterval(id) { timers.delete(id); },
  });
  vm.runInContext(sdk, context, { filename: "sdk.js" });
  context.SentinelPlugin = window.SentinelPlugin;
  vm.runInContext(app, context, { filename: "app.js" });
  await flush();
  const el = (id) => { const element = document.getElementById(id); assert.ok(element, id + " exists"); return element; };
  return {
    document, calls, timers, el, handlers,
    async click(id) { await el(id).dispatch("click"); await flush(); },
    async clickElement(element) { await element.dispatch("click"); await flush(); },
    async change(id, value) { if (typeof value === "boolean") el(id).checked = value; else el(id).value = value; await el(id).dispatch("change"); await flush(); },
    async input(id, value) { el(id).value = value; await el(id).dispatch("input"); await flush(); },
    async tick(ms) { for (const [id, timer] of [...timers]) { if (timer.ms !== ms) continue; if (!timer.repeat) timers.delete(id); await timer.fn(); } await flush(); },
    tools() { return calls.filter((call) => call.method === "tool.call").map((call) => ({ name: call.params.name, args: call.params.arguments })); },
    async hide() { dispatch("pagehide", {}); await flush(); },
  };
}

let passed = 0;
async function test(name, fn) {
  await fn(); passed++; console.log("PASS " + name);
}

const online = () => response({ online: true, info: { model: "iPhone", os: "iOS" }, capabilities: { frida: true } });
const appRecord = { bundle_id: "com.example.app", name: '<img src=x onerror="alert(1)">', path: "/Applications/Test.app", executable: "Test" };
async function connectedHarness(handlers = {}) {
  const h = await harness({ handlers: { ios_device_connect: online, ios_apps_list: () => response({ apps: [appRecord] }), ...handlers } });
  await h.click("device-connect");
  await h.click("apps-refresh");
  await h.clickElement(h.el("apps-body").children[0].children[0].children[0]);
  return h;
}

await test("initialization only reads config and preserves blank secrets", async () => {
  const h = await harness({ config: { SSH_HOST: "192.0.2.1", SSH_PORT: "2222", SSH_USER: "root", SSH_FINGERPRINT: "SHA256:abc", SSH_PASSWORD: "must-never-render", SSH_PRIVATE_KEY: "must-never-render" }, configKeys: ["SSH_PASSWORD", "SSH_PRIVATE_KEY"] });
  assert.deepEqual(h.calls.map((call) => call.method), ["config.get"]);
  assert.equal(h.el("ssh-host").value, "192.0.2.1");
  assert.equal(h.el("ssh-port").value, "2222");
  assert.equal(h.el("ssh-password").value, "");
  assert.equal(h.el("ssh-private-key").value, "");
  assert.equal(h.el("device-poll").checked, false);
  assert.equal(h.el("job-poll").checked, false);
  assert.equal(h.el("test-start").disabled, true);
  assert.doesNotMatch(h.document.textContent, /must-never-render/);
  assert.equal(h.timers.size, 0);
});

await test("secret blanks are omitted, save clears inputs and locks for container restart", async () => {
  const h = await harness({ config: { SSH_HOST: "192.0.2.1" } });
  h.el("ssh-password").value = "   ";
  h.el("ssh-private-key").value = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
  h.el("ssh-passphrase").value = "sample-secret";
  await h.click("config-save");
  const values = h.calls.find((call) => call.method === "config.save").params.values;
  assert.equal(Object.hasOwn(values, "SSH_PASSWORD"), false);
  assert.equal(values.SSH_USER, "root");
  assert.equal(values.SSH_PORT, "22");
  assert.equal(values.SSH_KEY_PASSPHRASE, "sample-secret");
  assert.match(values.SSH_PRIVATE_KEY, /BEGIN PRIVATE KEY/);
  assert.equal(h.el("ssh-private-key").value, "");
  assert.equal(h.el("ssh-passphrase").value, "");
  assert.equal(h.el("device-connect").disabled, true);
  assert.match(h.el("notice").textContent, /重载/);
  await h.click("device-connect");
  assert.deepEqual(h.tools(), []);
});

await test("save failure never claims configuration was saved", async () => {
  const h = await harness({ config: { SSH_HOST: "192.0.2.1" }, saveError: "bridge disconnected" });
  h.el("ssh-password").value = "temporary";
  await h.click("config-save");
  assert.match(h.el("notice").textContent, /保存结果未确认/);
  assert.equal(h.el("ssh-password").value, "");
  assert.equal(h.el("config-save").disabled, true);
});

await test("fingerprint probe does not connect or silently trust", async () => {
  const h = await harness({ handlers: { ios_device_probe: () => response({ fingerprint: "SHA256:verified", host: "192.0.2.1" }) } });
  await h.click("device-probe");
  assert.equal(h.el("ssh-fingerprint").value, "");
  assert.equal(h.el("probe-panel").hidden, false);
  await h.click("fingerprint-use");
  assert.equal(h.el("ssh-fingerprint").value, "SHA256:verified");
  assert.deepEqual(h.tools().map((call) => call.name), ["ios_device_probe"]);
  assert.equal(h.calls.some((call) => call.method === "config.save"), false);
});

await test("connection enables ten-second polling; pause and failure stop it", async () => {
  let fail = false;
  const h = await harness({ handlers: { ios_device_connect: online, ios_device_status: () => { if (fail) throw new Error("SSH unreachable"); return online(); } } });
  await h.click("device-connect");
  assert.equal(h.el("device-poll").checked, true);
  assert.equal([...h.timers.values()].filter((timer) => timer.ms === 10000).length, 1);
  await h.tick(10000);
  assert.deepEqual(h.tools().at(-1), { name: "ios_device_status", args: { refresh: true } });
  await h.change("device-poll", false);
  const count = h.tools().length;
  await h.tick(10000);
  assert.equal(h.tools().length, count);
  await h.change("device-poll", true);
  fail = true;
  await h.tick(10000);
  assert.equal(h.el("device-poll").checked, false);
  assert.equal(h.el("test-start").disabled, true);
  assert.match(h.el("notice").textContent, /SSH unreachable/);
  assert.match(h.el("device-status").textContent, /未知/);
});

await test("connection error performs no retry or test start", async () => {
  const h = await harness({ handlers: { ios_device_connect: () => response({ error: "fingerprint mismatch" }, { isError: true }) } });
  await h.click("device-connect");
  assert.match(h.el("notice").textContent, /fingerprint mismatch/);
  assert.equal(h.timers.size, 0);
  assert.deepEqual(h.tools().map((call) => call.name), ["ios_device_connect"]);
});

await test("application selection and filtering render tool strings only as text", async () => {
  const h = await connectedHarness();
  assert.equal(h.el("test-start").disabled, false);
  assert.match(h.el("selected-app").textContent, /<img src=x/);
  const cell = h.el("apps-body").children[0].children[1];
  assert.equal(cell.textContent, appRecord.name);
  assert.equal(cell.children.length, 0);
  await h.input("apps-filter", "no-match");
  assert.match(h.el("apps-body").textContent, /没有匹配/);
  await h.input("apps-filter", "COM.EXAMPLE");
  assert.match(h.el("apps-count").textContent, /1 \/ 1/);
});

await test("application pages are collected in order before replacing the list", async () => {
  const pages = [];
  const h = await harness({ handlers: {
    ios_device_connect: online,
    ios_apps_list: (args) => {
      pages.push(args);
      return response(args.offset === 0
        ? { apps: Array.from({ length: 100 }, (_, i) => ({ bundle_id: "com.example.app" + i, name: "应用" + i })), total: 101, next_offset: 100 }
        : { apps: [{ bundle_id: "com.example.last", name: "末页应用" }], total: 101, next_offset: null });
    },
  } });
  await h.click("device-connect");
  await h.click("apps-refresh");
  assert.deepEqual(pages, [{ offset: 0, limit: 100 }, { offset: 100, limit: 100 }]);
  assert.equal(h.el("apps-body").children.length, 101);
  assert.match(h.el("apps-count").textContent, /101 \/ 101/);
  assert.match(h.el("apps-body").children.at(-1).textContent, /末页应用/);
});

await test("truncated or cyclic app pages do not erase the prior selected application", async () => {
  const h = await connectedHarness();
  h.handlers.ios_apps_list = () => response({ summary: "输出较大；完整结果见任务产物。" });
  await h.click("apps-refresh");
  assert.match(h.el("notice").textContent, /截断/);
  assert.equal(h.el("test-start").disabled, false);
  assert.match(h.el("selected-app").textContent, /com.example.app/);
  assert.equal(h.el("apps-body").children.length, 1);
  h.handlers.ios_apps_list = () => response({ apps: [{ bundle_id: "com.other.app", name: "新列表" }], next_offset: 0 });
  await h.click("apps-refresh");
  assert.match(h.el("notice").textContent, /分页偏移异常/);
  assert.match(h.el("apps-body").textContent, /com.example.app/);
});

await test("analysis job starts explicitly, meta variants decode, polling ends with task", async () => {
  const h = await connectedHarness({
    ios_test_start: () => response({ job_id: "job-1", status: "running" }, { meta: { trace: "host-meta" } }),
    ios_job_status: () => response({ job_id: "job-1", status: "completed", stage: "report", result: { summary: "done" }, artifacts: ["job-1/report.json"] }, { _meta: { trace: "mcp-meta" } }),
  });
  await h.click("test-start");
  assert.deepEqual(h.tools().at(-1), { name: "ios_test_start", args: { bundle_id: appRecord.bundle_id, mode: "client", duration: 30 } });
  assert.match(h.el("job-detail").textContent, /host-meta/);
  assert.equal(h.el("job-poll").checked, false);
  assert.equal(h.tools().filter((call) => call.name === "ios_job_status").length, 0);
  await h.change("job-poll", true);
  await h.tick(3000);
  assert.match(h.el("job-detail").textContent, /mcp-meta/);
  assert.equal(h.el("job-state").textContent, "completed");
  assert.equal(h.el("job-poll").checked, false);
  assert.equal(h.el("job-stop").disabled, true);
  assert.match(h.el("job-artifacts").textContent, /report.json/);
});

await test("current task stop targets the task ID and stops finished polling", async () => {
  const h = await connectedHarness({ ios_dump_start: () => response({ job_id: "dump-1", status: "running" }), ios_job_stop: () => response({ job_id: "dump-1", status: "stopped" }) });
  await h.click("dump-start");
  await h.change("job-poll", true);
  await h.click("job-stop");
  assert.deepEqual(h.tools().at(-1), { name: "ios_job_stop", args: { job_id: "dump-1" } });
  assert.equal(h.el("job-poll").checked, false);
  assert.equal(h.el("job-state").textContent, "stopped");
});

await test("Hook observes by default; replacement requires explicit equal-byte crypto inputs", async () => {
  const h = await connectedHarness({ ios_hook_start: () => response({ job_id: "hook-1", status: "running" }) });
  await h.click("hook-start");
  assert.deepEqual(h.tools().at(-1).args, { bundle_id: appRecord.bundle_id, duration: 30, profile: "network" });
  await h.change("hook-replace", true);
  assert.equal(h.el("hook-replace-fields").hidden, false);
  h.el("hook-from").value = "你好"; h.el("hook-to").value = "ab";
  await h.click("hook-start");
  assert.match(h.el("notice").textContent, /仅支持 crypto/);
  h.el("hook-profile").value = "crypto";
  await h.click("hook-start");
  assert.match(h.el("notice").textContent, /字节长度相等/);
  h.el("hook-to").value = "世界";
  await h.click("hook-start");
  assert.deepEqual(h.tools().at(-1).args, { bundle_id: appRecord.bundle_id, duration: 30, profile: "crypto", replace_from: "你好", replace_to: "世界" });
});

await test("proxy start and explicit rules use SDK, with device/CA conditions visible", async () => {
  const h = await connectedHarness({ ios_proxy_start: () => response({ job_id: "proxy-1", kind: "proxy", status: "running", stage: "capturing", connection: { device_proxy_port: 8080 } }), ios_proxy_rules_set: () => response({ applied_rules: 1 }) });
  assert.match(h.document.textContent, /手动设置可达的代理/);
  assert.match(h.document.textContent, /信任对应 CA/);
  await h.click("proxy-start");
  assert.deepEqual(h.tools().at(-1).args, { duration: 120, reverse: true });
  h.el("proxy-rules").value = '{"wrong":true}';
  await h.click("proxy-rules-save");
  assert.match(h.el("notice").textContent, /数组/);
  h.el("proxy-rules").value = '[{"url_contains":"/api/test/", "response_body":"test"}]';
  await h.click("proxy-rules-save");
  assert.deepEqual(h.tools().at(-1), { name: "ios_proxy_rules_set", args: { job_id: "proxy-1", rules: [{ url_contains: "/api/test/", response_body: "test" }] } });
});

await test("proxy boundaries and rule readiness match the real tool contract", async () => {
  const h = await connectedHarness({
    ios_proxy_start: () => response({ job_id: "proxy-2", kind: "proxy", status: "running", stage: "starting" }),
    ios_job_status: () => response({ job_id: "proxy-2", kind: "proxy", status: "running", stage: "capturing" }),
    ios_proxy_rules_set: () => response({ applied_rules: 1 }),
  });
  assert.equal(h.el("proxy-reverse").disabled, true);
  h.el("proxy-duration").value = "601";
  await h.click("proxy-start");
  assert.equal(h.tools().some((call) => call.name === "ios_proxy_start"), false);
  h.el("proxy-duration").value = "5";
  await h.click("proxy-start");
  assert.deepEqual(h.tools().at(-1).args, { duration: 5, reverse: true });
  assert.equal(h.el("proxy-rules-save").disabled, true);
  await h.click("job-refresh");
  assert.equal(h.el("proxy-rules-save").disabled, false);
  h.el("proxy-rules").value = '[{"url_contains":"/api/","response_body":"x"}]';
  await h.click("proxy-rules-save");
  assert.match(h.el("notice").textContent, /8–2048/);
  assert.equal(h.tools().some((call) => call.name === "ios_proxy_rules_set"), false);
});

await test("API check validates URL and header JSON before any request", async () => {
  const h = await harness({ handlers: { ios_api_check: () => response({ job_id: "api-1", status: "queued" }) } });
  h.el("api-url").value = "javascript:alert(1)";
  await h.click("api-start");
  assert.equal(h.tools().length, 0);
  h.el("api-url").value = "https://example.test/api";
  h.el("api-headers").value = "[]";
  await h.click("api-start");
  assert.equal(h.tools().length, 0);
  h.el("api-headers").value = '{"Authorization":"Bearer sample"}';
  await h.click("api-start");
  assert.deepEqual(h.tools().at(-1), { name: "ios_api_check", args: { url: "https://example.test/api", method: "GET", base_headers: {}, headers: { Authorization: "Bearer sample" }, compare_headers: {} } });
});

await test("API headers reject newline injection and disclose optional-identity behavior", async () => {
  const h = await harness();
  assert.match(h.document.textContent, /基线仅使用通用请求头/);
  assert.match(h.document.textContent, /基线与身份对照使用相同方法、URL 和正文/);
  assert.match(h.document.textContent, /不会自动清除通用头、URL 或正文中的身份参数/);
  assert.doesNotMatch(h.document.textContent, /始终发送匿名基线请求/);
  assert.match(h.document.textContent, /空对象表示跳过/);
  h.el("api-url").value = "https://example.test/api";
  h.el("api-headers").value = JSON.stringify({ Test: "hello\r\nInjected: yes" });
  await h.click("api-start");
  assert.match(h.el("notice").textContent, /换行/);
  assert.equal(h.tools().length, 0);
});

await test("API POST sends the exact body, common headers and optional identity headers through the SDK", async () => {
  const h = await harness({ handlers: { ios_api_check: () => response({ job_id: "api-post", status: "queued" }) } });
  assert.equal(h.el("api-method").value, "GET");
  assert.equal(h.el("api-body").value, "");
  assert.equal(h.el("api-base-headers").value, "{}");
  assert.deepEqual(h.el("api-method").children.map((option) => option.value), ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
  await h.change("api-method", "POST");
  const body = ' {"orgId":"test-org","token":"body-identity","text":"你好"}\n';
  await h.input("api-body", body);
  h.el("api-url").value = "https://example.test/api?token=query-identity";
  h.el("api-base-headers").value = '{"Content-Type":"application/json","X-Test-Context":"fixture"}';
  h.el("api-headers").value = '{"Authorization":"Bearer test-A"}';
  h.el("api-compare").value = '{"Authorization":"Bearer test-B"}';
  assert.equal(h.tools().length, 0, "editing a request does not send it");
  await h.click("api-start");
  assert.deepEqual(h.tools(), [{ name: "ios_api_check", args: {
    url: "https://example.test/api?token=query-identity", method: "POST", body,
    base_headers: { "Content-Type": "application/json", "X-Test-Context": "fixture" },
    headers: { Authorization: "Bearer test-A" }, compare_headers: { Authorization: "Bearer test-B" },
  } }]);
  assert.equal(h.el("job-id").textContent, "api-post");
  assert.equal(h.calls.some((call) => call.method === "config.save"), false, "request credentials are not persisted to configuration");
});

await test("API supports each additional backend method and rejects an unsupported method before the tool", async () => {
  const h = await harness({ handlers: { ios_api_check: () => response({ job_id: "api-method", status: "queued" }) } });
  h.el("api-url").value = "https://example.test/api";
  h.el("api-body").value = "raw=request&value=unchanged";
  for (const method of ["HEAD", "PUT", "PATCH", "DELETE"]) {
    await h.change("api-method", method);
    await h.click("api-start");
    assert.equal(h.tools().at(-1).args.method, method);
    assert.equal(h.tools().at(-1).args.body, "raw=request&value=unchanged");
  }
  const count = h.tools().length;
  await h.change("api-method", "TRACE");
  await h.click("api-start");
  assert.equal(h.tools().length, count);
  assert.match(h.el("notice").textContent, /支持的 HTTP 请求方法/);
});

await test("API body limit uses schema characters and rejects oversized text without calling the tool", async () => {
  const h = await harness({ handlers: { ios_api_check: () => response({ job_id: "api-limit", status: "queued" }) } });
  h.el("api-url").value = "https://example.test/api";
  h.el("api-method").value = "POST";
  for (const body of ["a".repeat(65537), "😀".repeat(65537)]) {
    h.el("api-body").value = body;
    await h.click("api-start");
    assert.equal(h.tools().length, 0);
    assert.match(h.el("notice").textContent, /正文最多 65536/);
  }
  const body = "😀".repeat(65536);
  h.el("api-body").value = body;
  await h.click("api-start");
  assert.equal(h.tools().length, 1);
  assert.equal(h.tools()[0].args.body, body);
});

await test("API common headers use the same validation before any request", async () => {
  const h = await harness();
  h.el("api-url").value = "https://example.test/api";
  for (const input of ["{", "[]", '{"Content-Type":123}', JSON.stringify({ Test: "line\r\nbreak" })]) {
    h.el("api-base-headers").value = input;
    await h.click("api-start");
    assert.equal(h.tools().length, 0);
    assert.equal(h.el("notice").getAttribute("role"), "alert");
  }
});

await test("task list selection refreshes once and reports failed task errors", async () => {
  const h = await harness({ handlers: {
    ios_jobs_list: () => response({ jobs: [{ job_id: "old-1", status: "running" }] }),
    ios_job_status: () => response({ job_id: "old-1", status: "failed", stage: "hook", error: "Frida unavailable", artifacts: [] }),
  } });
  await h.click("jobs-refresh");
  await h.clickElement(h.el("jobs-body").children[0].children[3].children[0]);
  assert.equal(h.el("job-state").textContent, "failed");
  assert.match(h.el("job-detail").textContent, /Frida unavailable/);
  assert.equal(h.el("job-stop").disabled, true);
  assert.equal(h.timers.size, 0);
});

await test("job list reads all summary pages and retains records on summary truncation", async () => {
  const pages = [];
  const h = await harness({ handlers: {
    ios_jobs_list: (args) => {
      pages.push(args);
      return response(args.offset === 0
        ? { jobs: Array.from({ length: 20 }, (_, i) => ({ job_id: "task-" + i, kind: "hook", status: "completed" })), total: 21, next_offset: 20 }
        : { jobs: [{ job_id: "task-20", kind: "proxy", status: "completed" }], total: 21, next_offset: null });
    },
  } });
  await h.click("jobs-refresh");
  assert.deepEqual(pages, [{ offset: 0, limit: 20 }, { offset: 20, limit: 20 }]);
  assert.equal(h.el("jobs-body").children.length, 21);
  h.handlers.ios_jobs_list = () => response({ summary: "结果已摘要" });
  await h.click("jobs-refresh");
  assert.match(h.el("notice").textContent, /截断/);
  assert.equal(h.el("jobs-body").children.length, 21);
});

await test("artifact paths supplied only through host meta remain previewable", async () => {
  const h = await connectedHarness({ ios_dump_start: () => response({ job_id: "dump-meta", status: "completed" }, { meta: { artifacts: ["dump-meta/report.json"] } }) });
  await h.click("dump-start");
  assert.match(h.el("job-artifacts").textContent, /dump-meta\/report.json/);
});

await test("artifact preview supports strings and path objects and never executes report HTML", async () => {
  const report = '<script>throw new Error("XSS")</script><h1>Report</h1>';
  const h = await harness({ handlers: {
    "artifact.list": () => ["reports/result.json", { path: "reports/view.html", size: 52 }, { path: "payload.ipa", size: 100 }, { path: "large.json", size: 1048577 }],
    "artifact.read": ({ path, encoding }) => { assert.equal(encoding, "text"); return { path, size: 52, encoding: "utf8", data: report }; },
  } });
  await h.click("artifacts-refresh");
  const rows = h.el("artifacts-list").children;
  assert.equal(rows.length, 4);
  assert.equal(rows[2].children[1].tagName, "SPAN");
  assert.equal(rows[3].children[1].tagName, "SPAN");
  await h.clickElement(rows[1].children[1]);
  assert.equal(h.el("artifact-preview").textContent, report);
  assert.equal(h.el("artifact-preview").children.length, 0);
  assert.equal(h.el("artifact-name").textContent, "reports/view.html");
});

await test("container-restart interrupted tasks are terminal and cannot keep polling", async () => {
  const h = await harness({ handlers: {
    ios_jobs_list: () => response({ jobs: [{ job_id: "restart-1", status: "interrupted", error: "插件重启，任务中断" }] }),
    ios_job_status: () => response({ job_id: "restart-1", status: "interrupted", error: "插件重启，任务中断" }),
  } });
  await h.click("jobs-refresh");
  await h.clickElement(h.el("jobs-body").children[0].children[3].children[0]);
  assert.equal(h.el("job-stop").disabled, true);
  assert.equal(h.el("job-poll").disabled, true);
  assert.equal(h.el("job-poll").checked, false);
  assert.match(h.el("job-detail").textContent, /任务中断/);
});

await test("malformed MCP text is visible as an error, not a successful empty result", async () => {
  const h = await harness({ handlers: { ios_device_connect: () => ({ content: [{ type: "text", text: "not JSON <img>" }] }) } });
  await h.click("device-connect");
  assert.match(h.el("notice").textContent, /not JSON <img>/);
  assert.equal(h.el("notice").children.length, 0);
  assert.equal(h.el("device-poll").checked, false);
});

await test("IPA upload chunks at 256 KiB, validates offsets, and creates a task only on finish", async () => {
  const chunks = [];
  const file = new Blob([Buffer.alloc(262144 + 19, 0x42)]); file.name = "sample.ipa";
  const h = await harness({ handlers: {
    ios_package_import_start: (args) => { assert.deepEqual(args, { filename: "sample.ipa", size: file.size }); return response({ upload_id: "upload-1" }); },
    ios_package_import_chunk: (args) => { const bytes = Buffer.from(args.data_base64, "base64"); chunks.push(bytes); assert.ok(bytes.length <= 262144); assert.ok(args.data_base64.length < 524288); return response({ offset: args.offset + bytes.length }); },
    ios_package_import_finish: () => response({ job_id: "import-1", status: "queued" }),
  } });
  h.el("package-file").files = [file];
  await h.click("package-upload");
  assert.deepEqual(chunks.map((part) => part.length), [262144, 19]);
  assert.deepEqual(Buffer.concat(chunks), Buffer.from(await file.arrayBuffer()));
  assert.equal(h.el("job-id").textContent, "import-1");
  assert.match(h.el("package-progress").textContent, /上传完成/);
  assert.equal(h.tools().at(-1).name, "ios_package_import_finish");
});

await test("IPA wrong offset stops before finish and restores controls", async () => {
  const file = new Blob(["IPA contents"]); file.name = "sample.zip";
  const h = await harness({ handlers: { ios_package_import_start: () => response({ upload_id: "upload-2" }), ios_package_import_chunk: () => response({ offset: 999 }), ios_package_import_cancel: () => response({ cancelled: "upload-2" }) } });
  h.el("package-file").files = [file];
  await h.click("package-upload");
  assert.match(h.el("notice").textContent, /偏移不一致/);
  assert.equal(h.tools().some((call) => call.name === "ios_package_import_finish"), false);
  assert.deepEqual(h.tools().at(-1), { name: "ios_package_import_cancel", args: { upload_id: "upload-2" } });
  assert.equal(h.el("package-upload").disabled, false);
  assert.equal(h.el("package-cancel").disabled, true);
});

await test("IPA uppercase extension is normalized without altering the actual file bytes", async () => {
  const file = new Blob(["test bytes"]); file.name = "Example.IPA";
  const h = await harness({ handlers: {
    ios_package_import_start: (args) => { assert.equal(args.filename, "Example.ipa"); return response({ upload_id: "upper-upload" }); },
    ios_package_import_chunk: (args) => { assert.equal(Buffer.from(args.data_base64, "base64").toString(), "test bytes"); return response({ offset: file.size }); },
    ios_package_import_finish: () => response({ job_id: "upper-job", status: "queued" }),
  } });
  h.el("package-file").files = [file];
  await h.click("package-upload");
  assert.match(h.el("package-progress").textContent, /上传完成/);
});

await test("IPA cancellation stops after current chunk without starting analysis", async () => {
  let release;
  const file = new Blob([Buffer.alloc(262145)]); file.name = "cancel.ipa";
  const h = await harness({ handlers: { ios_package_import_start: () => response({ upload_id: "upload-3" }), ios_package_import_chunk: () => new Promise((resolve) => { release = resolve; }), ios_package_import_cancel: () => response({ cancelled: "upload-3" }) } });
  h.el("package-file").files = [file];
  const pending = h.click("package-upload");
  await flush();
  assert.equal(h.el("package-cancel").disabled, false);
  await h.click("package-cancel");
  release(response({ offset: 262144 }));
  await pending;
  assert.equal(h.tools().filter((call) => call.name === "ios_package_import_chunk").length, 1);
  assert.equal(h.tools().some((call) => call.name === "ios_package_import_finish"), false);
  assert.deepEqual(h.tools().at(-1), { name: "ios_package_import_cancel", args: { upload_id: "upload-3" } });
  assert.match(h.el("package-progress").textContent, /已取消/);
});

await test("page hide clears credential fields and polling timers", async () => {
  const h = await connectedHarness({ ios_test_start: () => response({ job_id: "job-hide", status: "running" }) });
  await h.click("test-start");
  await h.change("job-poll", true);
  h.el("ssh-password").value = "temporary";
  await h.hide();
  assert.equal(h.el("ssh-password").value, "");
  assert.equal(h.el("device-poll").checked, false);
  assert.equal(h.el("job-poll").checked, false);
  assert.equal(h.timers.size, 0);
});

console.log(`\n${passed} UI event tests passed; SDK and CSS identity / security / overflow assertions passed.`);
