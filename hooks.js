'use strict';
// Native Objective-C runtime calls work without the version-specific ObjC bridge.
const options = __OPTIONS__;
let count = 0;
const attached = new Set();
function exported(name) {
  return typeof Module.findGlobalExportByName === 'function' ? Module.findGlobalExportByName(name) : Module.findExportByName(null, name);
}
function emit(event, data) {
  if (++count > 2000) return;
  // The native length describes the whole buffer; the attached bytes are only
  // a bounded prefix. A failed read must not look like an empty complete body.
  const originalLength = event.length === undefined ? event.body_length : event.length;
  if (Number.isFinite(originalLength) && originalLength >= 0) {
    event.original_length = originalLength;
    event.captured_length = data ? data.byteLength : 0;
    event.capture_available = data !== null && data !== undefined;
    event.truncated = event.captured_length < originalLength;
  }
  send(Object.assign({time: Date.now(), profile: options.profile}, event), data || null);
}
function attach(address, callbacks, name) {
  if (!address || attached.has(address.toString())) return;
  Interceptor.attach(address, callbacks);
  attached.add(address.toString());
  emit({type:'hook_installed', name});
}
function bytes(address, length) {
  try { return address.readByteArray(Math.min(Math.max(Number(length), 0), 8192)); } catch (_) { return null; }
}
function hookCrypto() {
  attach(exported('CCCrypt'), {
    onEnter(args) {
      this.operation = args[0].toInt32();
      this.output = args[8]; this.moved = args[10];
      let data = bytes(args[6], args[7].toUInt32());
      if (this.operation === 0 && options.replace_from && data) {
        const from = options.from_bytes, to = options.to_bytes;
        const input = new Uint8Array(data);
        let changed = false;
        if (args[7].toUInt32() <= 8192 && from.length === to.length && from.length) {
          for (let i=0; i<=input.length-from.length; i++) {
            if (from.every((v,j)=>input[i+j]===v)) {
              input.set(to,i); changed=true; i += from.length-1;
            }
          }
        }
        if (changed) {
          this.replacement=Memory.alloc(input.length); this.replacement.writeByteArray(input);
          args[6]=this.replacement; data=input.buffer;
          emit({type:'crypto_input_mutation', function:'CCCrypt', bytes:input.length,
            scope:'process_cccrypt_encrypt_input', network_request_verified:false});
        }
      }
      // Never collect key or IV arguments.
      emit({type:'crypto_input', function:'CCCrypt', operation:this.operation, length:args[7].toUInt32()},data);
    },
    onLeave(ret) {
      if (ret.toInt32() === 0 && !this.moved.isNull()) {
        try {
        const n=Process.pointerSize===8 ? Number(this.moved.readU64()) : this.moved.readU32();
        emit({type:'crypto_output', function:'CCCrypt', operation:this.operation, length:n},bytes(this.output,n));
        } catch (e) { emit({type:'observation_error',function:'CCCrypt',message:String(e)}); }
      }
    }
  }, 'CCCrypt');
  attach(exported('CCCryptorUpdate'), {
    onEnter(args) { this.out=args[3];this.moved=args[5];emit({type:'crypto_chunk_input',function:'CCCryptorUpdate',length:args[2].toUInt32()},bytes(args[1],args[2].toUInt32())); },
    onLeave(ret) { if(ret.toInt32()===0 && !this.moved.isNull()) {try {const n=Process.pointerSize===8?Number(this.moved.readU64()):this.moved.readU32();emit({type:'crypto_chunk_output',function:'CCCryptorUpdate',length:n},bytes(this.out,n));}catch(e){emit({type:'observation_error',function:'CCCryptorUpdate',message:String(e)});}} }
  }, 'CCCryptorUpdate');
}
function hookNetwork() {
  const getClassP=exported('objc_getClass'), selP=exported('sel_registerName');
  if (!getClassP || !selP) return;
  const getClass=new NativeFunction(getClassP,'pointer',['pointer']);
  const sel=new NativeFunction(selP,'pointer',['pointer']);
  const getMethod=new NativeFunction(exported('class_getInstanceMethod'),'pointer',['pointer','pointer']);
  const imp=new NativeFunction(exported('method_getImplementation'),'pointer',['pointer']);
  const msg=new NativeFunction(exported('objc_msgSend'),'pointer',['pointer','pointer']);
  const length=new NativeFunction(exported('objc_msgSend'),'ulong',['pointer','pointer']);
  const encodedLength=new NativeFunction(exported('objc_msgSend'),'ulong',['pointer','pointer','ulong']);
  const selector=(s)=>sel(Memory.allocUtf8String(s));
  const str=(obj)=>obj.isNull()?'':msg(obj,selector('UTF8String')).readUtf8String(Math.min(4096,Number(encodedLength(obj,selector('lengthOfBytesUsingEncoding:'),4))));
  const readRequest=(request)=> {
    try {
      const url=msg(msg(request,selector('URL')),selector('absoluteString'));
      const method=msg(request,selector('HTTPMethod'));
      const body=msg(request,selector('HTTPBody'));
      let binary=null,n=0;
      if (!body.isNull()) { n=Number(length(body,selector('length'))); binary=bytes(msg(body,selector('bytes')),n); }
      emit({type:'http_request',url:str(url),method:str(method),body_length:n},binary);
    } catch(e) { emit({type:'observation_error',message:String(e)}); }
  };
  ['NSURLSession','__NSURLSessionLocal','__NSCFURLSession'].forEach(name=>{
    const klass=getClass(Memory.allocUtf8String(name));
    if(klass.isNull()) return;
    ['dataTaskWithRequest:completionHandler:','dataTaskWithRequest:','uploadTaskWithRequest:fromData:completionHandler:','downloadTaskWithRequest:completionHandler:'].forEach(method=>{
      const m=getMethod(klass,selector(method));
      if(!m.isNull()) attach(imp(m),{onEnter(args){readRequest(args[2]);}},name+' '+method);
    });
  });
  ['SSL_read','SSL_write'].forEach(name=>attach(exported(name),{
    onEnter(args){ this.ptr=args[1];this.n=args[2].toInt32();if(name==='SSL_write') emit({type:'tls_plaintext_write',function:name,length:this.n},bytes(this.ptr,this.n)); },
    onLeave(ret){if(name==='SSL_read' && ret.toInt32()>0) emit({type:'tls_plaintext_read',function:name,length:ret.toInt32()},bytes(this.ptr,ret.toInt32()));}
  },name));
}
function hookStorage() {
  attach(exported('open'),{onEnter(args){try{emit({type:'file_open',path:args[0].readUtf8String(4096),flags:args[1].toInt32()});}catch(_){}}},'open');
  attach(exported('SecItemCopyMatching'),{onLeave(ret){emit({type:'keychain_access',status:ret.toInt32()});}},'SecItemCopyMatching');
}
function install() {
  try {
    if(options.profile==='crypto') hookCrypto();
    if(options.profile==='network') hookNetwork();
    if(options.profile==='storage') hookStorage();
  }catch(e){emit({type:'setup_error',message:String(e)});}
}
install();
const timer=setInterval(install,1000);
rpc.exports={stats(){return {installed_hooks:attached.size,events:count,limit:2000};}};
