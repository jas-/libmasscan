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

    lm.Report(masscan, ip, ip_proto, port, reason, ttl);
  }
}

void libmasscan::Intermediary(Masscan *masscan, unsigned ip, unsigned ip_proto,
                        unsigned port, unsigned reason, unsigned ttl) {
  libmasscan lm;

  lm.Report(masscan, ip, ip_proto, port, reason, ttl);
}

void libmasscan::Report(Masscan *masscan, unsigned ip, unsigned ip_proto,
                        unsigned port, unsigned reason, unsigned ttl) {
   libmasscan lm;

  //Local<Object> obj = Object::New();
  //v8::Persistent<v8::Object> pobj(v8::Persistent<v8::Object>::New(obj));

  /* Create object out of supplied IP if it doesn't exist */
  /* If object with key of IP exists add new object to it */

//  if (masscan->is_offline) {
    //lm.RunCallback(pobj);
//  }
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
