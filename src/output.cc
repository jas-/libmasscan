#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

using namespace node;
using namespace v8;

extern "C" {
  #include "masscan/src/logger.h"
  #include "masscan/src/ranges.h"
  void ReturnObject(Masscan *masscan, unsigned ip, unsigned ip_proto,
                    unsigned port, unsigned reason, unsigned ttl) {
    libmasscan lm;

    lm.Intermediary(masscan, ip, ip_proto, port, reason, ttl);
  }
}

void libmasscan::Intermediary(Masscan *masscan, unsigned ip, unsigned ip_proto,
                              unsigned port, unsigned reason, unsigned ttl) {
  libmasscan lm;
  Baton *baton = new Baton();
  uv_work_t req;

  baton->callback = Persistent<Function>::New(lm.cb);

  uv_async_init(uv_default_loop(), &baton->async, Report);
  //uv_queue_work(uv_default_loop(), &req, fake_download, after);

  CreateObject(baton, masscan, ip, ip_proto, port, reason, ttl);
}

void CreateObject(Baton* handle, Masscan *masscan, unsigned ip,
                  unsigned ip_proto, unsigned port, unsigned reason,
                  unsigned ttl) {

  Results *results = new Results();

  results->masscan = masscan;
  results->ip = ip;
  results->ip_proto = ip_proto;
  results->port = port;
  results->reason = reason;
  results->ttl = ttl;

  handle->async.data = results;

  uv_async_send(&handle->async);
}

void Report(uv_async_t *handle, int status) {
  HandleScope scope;
  libmasscan lm;

  Persistent<Function> cb = Persistent<Function>::Cast(lm.cb);

/*
  Baton *baton = static_cast<Baton*>(handle->data);
  Persistent<Function> cb = Persistent<Function>::Cast(baton->callback);
*/

  Results *results = static_cast<Results*>(handle->data);
  Masscan *masscan = static_cast<Masscan*>(results->masscan);

  Local<Object> ret = Object::New();
	Local<Object> obj = Object::New();
	Local<Object> res = Object::New();
  Handle<Object> summary = Handle<Object>::Cast(Summary(masscan));

  if (!res->Has(results->ip)) {
    res->Set(Uint32::New(results->ip), obj);
  }

  obj->Set(String::NewSymbol("port"), Uint32::New(results->port));
  ret->Set(String::NewSymbol("summary"), summary);

  uv_close((uv_handle_t*) &handle, 0);

  const unsigned argc = 2;
  Local<Value> argv[argc] = {
    Local<Value>::New(Null()),
    Local<Value>::New(ret)
  };

  if (v8::Context::InContext()) {
    cb->Call(v8::Context::GetCurrent()->Global(), argc, argv);
  }

  //baton->callback.Dispose();
  //baton->data.Dispose();
  //delete baton;
}

Handle<Object> Summary(Masscan masscan[1]) {
	HandleScope scope;

	Local<Object> obj = Object::New();
	Local<Object> cnf = Object::New();
	Local<Object> stat = Object::New();

/*
  cnf->Set(String::NewSymbol("total-targets"),
					 Uint32::New(rangelist_count(&masscan->targets)));

  cnf->Set(String::NewSymbol("total-target-ports"),
					 Uint32::New(rangelist_count(&masscan->ports)));

  cnf->Set(String::NewSymbol("total-blacklisted-targets"),
					 Uint32::New(rangelist_count(&masscan->exclude_ip)));

  cnf->Set(String::NewSymbol("total-blacklisted-ports"),
					 Uint32::New(rangelist_count(&masscan->exclude_port)));

  cnf->Set(String::NewSymbol("total-packets"),
					 Uint32::New(rangelist_count(&masscan->targets) *
                       rangelist_count(&masscan->ports)));
*/
	obj->Set(String::NewSymbol("configuration"), cnf);
	obj->Set(String::NewSymbol("statistics"), stat);

	return scope.Close(obj);
}

Handle<Value> libmasscan::RunCallback(Handle<Object> obj) {
  HandleScope scope;

  const unsigned argc = 2;
  Local<Value> argv[argc] = {
    Local<Value>::New(Null()),
    Local<Value>::New(obj)
  };

  return cb->Call(Context::GetCurrent()->Global(), argc, argv);
}
