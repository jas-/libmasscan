#ifndef LIBMASSCAN_H
#define LIBMASSCAN_H

#include <node.h>
#include <string>

extern "C" {
  #include "masscan/src/masscan.h"
}

struct Baton {
  int error;
  std::string error_message;
  uv_async_t async;

  v8::Persistent<v8::Object> data;
  v8::Persistent<v8::Function> callback;
};

struct Results {
  struct Masscan *masscan;
  unsigned ip;
  unsigned ip_proto;
  unsigned port;
  unsigned reason;
  unsigned ttl;
};

void Report(uv_async_t *handle, int status);

class libmasscan : public node::ObjectWrap {
	public:
    v8::Persistent<v8::Function> cb;
		static void Init(v8::Handle<v8::Object> exports);
    void Intermediary(struct Masscan *masscan, unsigned ip, unsigned ip_proto,
                      unsigned port, unsigned reason, unsigned ttl);

	protected:
		void Config(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigFile(v8::Handle<v8::Object> obj);
		void ConfigLoglevel(v8::Handle<v8::Object> obj);
		void ConfigIface(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigHwaddr(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigIpaddr(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigGatewayMac(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigRange(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigPorts(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigExcludeRange(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigExcludePorts(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigBlacklist(v8::Handle<v8::Object> obj);
    void ConfigBandwidth(v8::Handle<v8::Object> obj);

    v8::Handle<v8::Value> Summary(struct Masscan *masscan);
    v8::Handle<v8::Value> Scan(struct Masscan *masscan);
    v8::Handle<v8::Value> RunCallback(v8::Handle<v8::Object> obj);
    static v8::Handle<v8::Value> LibMasscan(const v8::Arguments& args);

	private:

};

#endif
