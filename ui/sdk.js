/**
 * Sentinel plugin UI SDK.
 *
 * The console opens this document inside `<iframe sandbox="allow-scripts">`, so
 * the page has an opaque origin: it cannot read the console's cookies, storage,
 * or DOM. Everything goes through this postMessage bridge, and the console
 * validates the nonce, the source window, and the method before acting.
 *
 * Copy this file next to your `index.html` and include it with a relative path.
 */
(function () {
	"use strict";

	var nonceMatch = /[#&]nonce=([^&]+)/.exec(window.location.hash);
	var nonce = nonceMatch ? decodeURIComponent(nonceMatch[1]) : "";
	var pending = new Map();
	var sequence = 0;
	var context = null;
	var resolveReady;
	var rejectReady;
	var ready = new Promise(function (resolve, reject) {
		resolveReady = resolve;
		rejectReady = reject;
	});
	var helloMessage = { kind: "sentinel-ui:hello", protocol: 1, nonce: nonce };
	var helloRetry = null;
	var handshakeTimer = setTimeout(function () {
		if (helloRetry) clearInterval(helloRetry);
		rejectReady(new Error("连接控制台超时：页面可能不是由哨兵打开的"));
	}, 10000);

	function request(method, params) {
		return ready.then(function () {
			return new Promise(function (resolve, reject) {
				var id = "c" + ++sequence;
				var timer = setTimeout(function () {
					pending.delete(id);
					reject(new Error("请求超时"));
				}, 300000);
				pending.set(id, {
					resolve: function (value) {
						clearTimeout(timer);
						resolve(value);
					},
					reject: function (error) {
						clearTimeout(timer);
						reject(error);
					},
				});
				window.parent.postMessage(
					{ kind: "sentinel-ui:call", id: id, method: method, params: params || {} },
					"*",
				);
			});
		});
	}

	window.addEventListener("message", function (event) {
		if (event.source !== window.parent) return;
		var data = event.data;
		if (!data || typeof data !== "object") return;

		if (data.kind === "sentinel-ui:init") {
			clearTimeout(handshakeTimer);
			if (helloRetry) clearInterval(helloRetry);
			context = data.context || null;
			resolveReady(api);
			return;
		}

		if (data.kind === "sentinel-ui:result") {
			var entry = pending.get(data.id);
			if (!entry) return;
			pending.delete(data.id);
			if (data.ok) entry.resolve(data.result);
			else entry.reject(new Error(data.error || "调用失败"));
		}
	});

	var api = {
		/** Handshake context: plugin, host, project name, tools, configured keys. */
		get context() {
			return context;
		},
		/** Raw bridge call; prefer the named helpers below. */
		call: request,
		callTool: function (name, args) {
			return request("tool.call", { name: name, arguments: args || {} });
		},
		listArtifacts: function () {
			return request("artifact.list", {});
		},
		readArtifact: function (path, encoding) {
			return request("artifact.read", { path: path, encoding: encoding || "text" });
		},
		getConfig: function () {
			return request("config.get", {});
		},
		saveConfig: function (values) {
			return request("config.save", { values: values || {} });
		},
		storage: {
			get: function (key) {
				return request("storage.get", { key: key });
			},
			set: function (key, value) {
				return request("storage.set", { key: key, value: value });
			},
			delete: function (key) {
				return request("storage.delete", { key: key });
			},
		},
	};

	window.SentinelPlugin = {
		protocol: 1,
		connect: function () {
			return ready;
		},
	};

	// The console attaches its listener after the iframe mounts, so a single
	// hello can race it. Retry until init arrives or the handshake times out.
	window.parent.postMessage(helloMessage, "*");
	helloRetry = setInterval(function () {
		window.parent.postMessage(helloMessage, "*");
	}, 400);
})();
