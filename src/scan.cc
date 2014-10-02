#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

extern "C" {

}

using namespace node;
using namespace v8;

Handle<Value> libmasscan::Scan(struct Masscan *masscan) {
  HandleScope scope;

  return scope.Close(Undefined());
}
