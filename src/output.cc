extern "C" {

}

#include "libzmap.h"

using namespace node;
using namespace v8;

Handle<Value> libzmap::Summary(void) {
	HandleScope scope;

	Local<Object> obj = Object::New();
	Local<Object> cnf = Object::New();
	Local<Object> stat = Object::New();

	obj->Set(String::NewSymbol("configuration"), cnf);
	obj->Set(String::NewSymbol("statistics"), stat);

	return scope.Close(obj);
}
