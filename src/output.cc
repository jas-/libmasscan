extern "C" {
  #include "masscan/src/masscan.h"
}

#include "libzmap.h"

using namespace node;
using namespace v8;

Handle<Value> libzmap::Summary(Masscan masscan[1]) {
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
