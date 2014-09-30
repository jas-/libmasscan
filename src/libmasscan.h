#ifndef LIBMASSCAN_H
#define LIBMASSCAN_H

#include <node.h>
#include <string>

extern "C" {
  #include "masscan/src/masscan.h"

}

class libmasscan : public node::ObjectWrap {
	public:
		static void Init(v8::Handle<v8::Object> exports);

	protected:
		void Config(v8::Handle<v8::Object> obj);
		void ConfigFile(v8::Handle<v8::Object> obj);
		void ConfigLoglevel(v8::Handle<v8::Object> obj);
		void ConfigIface(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigIpaddr(v8::Handle<v8::Object> obj);
		void ConfigHwaddr(v8::Handle<v8::Object> obj);
		void ConfigRange(v8::Handle<v8::Object> obj, Masscan masscan[1]);
		void ConfigBlacklist(v8::Handle<v8::Object> obj);
		void ConfigShards(v8::Handle<v8::Object> obj);
		void ConfigShardTotal(v8::Handle<v8::Object> obj);
		void ConfigProbeModule(v8::Handle<v8::Object> obj);
		void ConfigOutputModule(v8::Handle<v8::Object> obj);
    void ConfigBandwidth(v8::Handle<v8::Object> obj);
    void ConfigThreads(v8::Handle<v8::Object> obj);
		void ConfigTargets(void);
		void ConfigCores(void);
		void ConfigSeed(void);

    void Threads(void);

    v8::Handle<v8::Value> Summary(void);
		static v8::Handle<v8::Value> LibMasscan(const v8::Arguments& args);

	private:

};

#endif
