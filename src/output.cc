#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

using namespace node;
using namespace v8;

extern "C" {
  #include "masscan/src/logger.h"
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
  Results *results = new Results();

  baton->callback = Persistent<Function>::New(lm.cb);

  uv_async_init(uv_default_loop(), &baton->async, Report);

  results->masscan = masscan;
  results->ip = ip;
  results->ip_proto = ip_proto;
  results->port = port;
  results->reason = reason;
  results->ttl = ttl;

  baton->async.data = results;
}

void Report(uv_async_t *handle, int status) {
  HandleScope scope;
  libmasscan lm;

  Local<Object> obj = Object::New();
  v8::Persistent<v8::Object> pobj(v8::Persistent<v8::Object>::New(obj));

  /* Create object out of supplied IP if it doesn't exist */
  /* If object with key of IP exists add new object to it */

  //if (handle->masscan->is_offline) {
  //  lm.RunCallback(pobj);
  //}
  const unsigned argc = 2;
  Local<Value> argv[argc] = {
    Local<Value>::New(Null()),
    Local<Value>::New(pobj)
  };

  lm.cb->Call(Context::GetCurrent()->Global(), argc, argv);
}

Handle<Value> libmasscan::Summary(Masscan masscan[1]) {
	HandleScope scope;

	Local<Object> obj = Object::New();
	Local<Object> cnf = Object::New();
	Local<Object> stat = Object::New();

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
