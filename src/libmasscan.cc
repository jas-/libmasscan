#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

using namespace node;
using namespace v8;

Handle<Value> libmasscan::LibMasscan(const Arguments& args) {
	HandleScope scope;
	libmasscan masscan;

	Local<Function> callback;
	Local<Object> obj;

	if (args.Length() < 1) {
		ThrowException(Exception::TypeError(String::New("Arguments invalid")));
		return scope.Close(Undefined());
	}

	if (args[0]->IsFunction()) {
		callback = Local<Function>::Cast(args[0]);
	} else {
		if (!args[1]->IsFunction()) {
			ThrowException(Exception::TypeError(String::New("Function expected")));
			return scope.Close(Undefined());
		}

		callback = Local<Function>::Cast(args[1]);

		if (!args[0]->IsObject()) {
			ThrowException(Exception::TypeError(String::New("Object expected")));
			return scope.Close(Undefined());
		}
	}

	if (args[0]->IsObject()) {
    obj = args[0]->ToObject();
    masscan.Config(obj);
  }

//  masscan.Threads();

  const unsigned argc = 2;
  Local<Value> argv[argc] = {
    Local<Value>::New(Null()),
    Local<Value>::New(obj)
  };

  return callback->Call(Context::GetCurrent()->Global(), argc, argv);
}

void libmasscan::Init (Handle<Object> exports) {
	exports->Set(String::NewSymbol("masscan"),
			FunctionTemplate::New(LibMasscan)->GetFunction());
}

extern "C" {
	NODE_MODULE(masscan, libmasscan::Init)
}
