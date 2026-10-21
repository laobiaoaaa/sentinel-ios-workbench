// Execute the production Hook script against an in-memory Frida API fixture.
// No device, network, Frida server, or target process is used.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../hooks.js", import.meta.url), "utf8");

class Pointer {
  constructor(name, buffer = null, value = 0) {
    this.name = name;
    this.buffer = buffer;
    this.value = value;
    this.fields = {};
  }
  toString() { return this.name; }
  isNull() { return this.name === "NULL"; }
  toInt32() { return Number(this.value); }
  toUInt32() { return Number(this.value); }
  readU32() { return this.buffer.readUInt32LE(); }
  readU64() { return this.buffer.readBigUInt64LE(); }
  readByteArray(length) {
    if (!this.buffer || length > this.buffer.length) throw new Error("unreadable fixture memory");
    const bytes = this.buffer.subarray(0, length);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }
  writeByteArray(value) { Buffer.from(value).copy(this.buffer); }
  readUtf8String(length) {
    if (!this.buffer) throw new Error("unreadable fixture string");
    const end = length === undefined ? this.buffer.indexOf(0) : length;
    return this.buffer.subarray(0, end < 0 ? undefined : end).toString("utf8");
  }
}

const nil = new Pointer("NULL");
const integer = (value) => new Pointer("integer", null, value);
const memory = (value) => new Pointer("memory", Buffer.from(value));
const cstring = (value) => memory(Buffer.from(value + "\0"));
function sizePointer(value) {
  const result = memory(Buffer.alloc(8));
  result.buffer.writeBigUInt64LE(BigInt(value));
  return result;
}
function stringObject(value) {
  const result = new Pointer("NSString");
  result.fields = { UTF8String: cstring(value), "lengthOfBytesUsingEncoding:": Buffer.byteLength(value) };
  return result;
}

function fixture(profile, replacement = {}) {
  const events = [], callbacks = new Map();
  const options = { profile, replace_from: "", replace_to: "", ...replacement };
  options.from_bytes = [...Buffer.from(options.replace_from)];
  options.to_bytes = [...Buffer.from(options.replace_to)];
  const native = {
    objc_getClass: (name) => name.readUtf8String() === "NSURLSession" ? new Pointer("NSURLSession") : nil,
    sel_registerName: (name) => name,
    class_getInstanceMethod: (_klass, selector) => new Pointer(selector.readUtf8String()),
    method_getImplementation: (method) => method,
    objc_msgSend: (object, selector) => object.fields[selector.readUtf8String()] ?? nil,
  };
  const supported = new Set(["CCCrypt", "CCCryptorUpdate", "SSL_read", "SSL_write", ...Object.keys(native)]);
  const context = vm.createContext({
    Module: { findGlobalExportByName: (name) => supported.has(name) ? new Pointer(name) : null },
    NativeFunction: function (address) { return native[address.name]; },
    Memory: { alloc: (length) => memory(Buffer.alloc(length)), allocUtf8String: cstring },
    Interceptor: { attach: (address, handlers) => callbacks.set(address.name, handlers) },
    Process: { pointerSize: 8 },
    send: (event, data) => events.push({ ...JSON.parse(JSON.stringify(event)), captured: data ? Buffer.from(data) : null }),
    setInterval: () => 1,
    rpc: { exports: {} },
  });
  vm.runInContext(source.replace("__OPTIONS__", JSON.stringify(options)), context);
  return { events, callbacks };
}

function observeCCCrypt(f, input, output, operation = 0) {
  const args = Array.from({ length: 11 }, () => nil);
  args[0] = integer(operation);
  args[6] = memory(input);
  args[7] = integer(input.length);
  args[8] = memory(output);
  args[10] = sizePointer(output.length);
  const invocation = {};
  f.callbacks.get("CCCrypt").onEnter.call(invocation, args);
  f.callbacks.get("CCCrypt").onLeave.call(invocation, integer(0));
  return args;
}

let passed = 0;
function test(name, run) { run(); passed++; console.log("PASS " + name); }

test("CCCrypt reports whole lengths separately from captured prefixes", () => {
  const f = fixture("crypto");
  observeCCCrypt(f, Buffer.alloc(12000, 65), Buffer.alloc(12016, 66));
  for (const [type, size] of [["crypto_input", 12000], ["crypto_output", 12016]]) {
    const event = f.events.find((item) => item.type === type);
    assert.equal(event.original_length, size);
    assert.equal(event.captured_length, 8192);
    assert.equal(event.captured.length, 8192);
    assert.equal(event.truncated, true);
    assert.equal(event.capture_available, true);
  }
});

test("text replacement is a process crypto input mutation, not proof of a network change", () => {
  const f = fixture("crypto", { replace_from: "alpha", replace_to: "bravo" });
  const args = observeCCCrypt(f, Buffer.from("alpha alpha"), Buffer.from("ciphertext"));
  assert.equal(args[6].buffer.toString(), "bravo bravo");
  const mutation = f.events.find((item) => item.type === "crypto_input_mutation");
  assert.equal(mutation.scope, "process_cccrypt_encrypt_input");
  assert.equal(mutation.network_request_verified, false);
  assert.equal(f.events.some((item) => item.type === "request_mutation"), false);
  const input = f.events.find((item) => item.type === "crypto_input");
  assert.equal(input.captured.toString(), "bravo bravo");
  assert.equal(input.original_length, 11);
  assert.equal(input.captured_length, 11);
  assert.equal(input.truncated, false);
});

test("decrypt calls and oversized encrypt buffers are not replaced", () => {
  for (const [operation, input] of [[1, Buffer.from("alpha")], [0, Buffer.from("alpha".repeat(2000))]]) {
    const f = fixture("crypto", { replace_from: "alpha", replace_to: "bravo" });
    const args = observeCCCrypt(f, input, Buffer.from("output"), operation);
    assert.deepEqual(args[6].buffer, input);
    assert.equal(f.events.some((item) => item.type === "crypto_input_mutation"), false);
  }
});

test("CCCryptorUpdate input and output prefixes carry truncation metadata", () => {
  const f = fixture("crypto");
  const args = [nil, memory(Buffer.alloc(9000)), integer(9000), memory(Buffer.alloc(8192)), nil, sizePointer(8192)];
  const invocation = {}, handlers = f.callbacks.get("CCCryptorUpdate");
  handlers.onEnter.call(invocation, args);
  handlers.onLeave.call(invocation, integer(0));
  const input = f.events.find((item) => item.type === "crypto_chunk_input");
  const output = f.events.find((item) => item.type === "crypto_chunk_output");
  assert.equal(input.original_length, 9000);
  assert.equal(input.captured_length, 8192);
  assert.equal(input.truncated, true);
  assert.equal(output.original_length, 8192);
  assert.equal(output.captured_length, 8192);
  assert.equal(output.truncated, false);
});

test("unreadable nonempty buffers are unavailable rather than complete empty samples", () => {
  const f = fixture("crypto");
  const args = [nil, nil, integer(20), nil, nil, sizePointer(0)];
  f.callbacks.get("CCCryptorUpdate").onEnter.call({}, args);
  const event = f.events.find((item) => item.type === "crypto_chunk_input");
  assert.equal(event.original_length, 20);
  assert.equal(event.captured_length, 0);
  assert.equal(event.capture_available, false);
  assert.equal(event.truncated, true);
});

test("NSURLSession body and supported TLS observations expose their prefix limits", () => {
  const f = fixture("network");
  const data = new Pointer("NSData");
  data.fields = { length: 10000, bytes: memory(Buffer.alloc(10000)) };
  const url = new Pointer("NSURL");
  url.fields.absoluteString = stringObject("https://example.test/fixture");
  const request = new Pointer("NSURLRequest");
  request.fields = { URL: url, HTTPMethod: stringObject("POST"), HTTPBody: data };
  f.callbacks.get("dataTaskWithRequest:").onEnter([nil, nil, request]);
  const http = f.events.find((item) => item.type === "http_request");
  assert.equal(http.original_length, 10000);
  assert.equal(http.captured_length, 8192);
  assert.equal(http.truncated, true);
  assert.equal(http.url, "https://example.test/fixture");
  for (const [name, type] of [["SSL_read", "tls_plaintext_read"], ["SSL_write", "tls_plaintext_write"]]) {
    const handlers = f.callbacks.get(name), invocation = {};
    handlers.onEnter.call(invocation, [nil, memory(Buffer.alloc(9000)), integer(9000)]);
    handlers.onLeave.call(invocation, integer(9000));
    const event = f.events.find((item) => item.type === type);
    assert.equal(event.original_length, 9000);
    assert.equal(event.captured_length, 8192);
    assert.equal(event.truncated, true);
  }
});

console.log(`${passed} Hook fixture tests passed`);
