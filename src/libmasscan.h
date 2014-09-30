#ifndef LIBMASSCAN_H
#define LIBMASSCAN_H

#include <node.h>
#include <string>

extern "C" {

}

class libmasscan : public node::ObjectWrap {
	public:
		static void Init(v8::Handle<v8::Object> exports);

	protected:

		int max(int a, int b);
 		//int parse_mac(macaddr_t *out, char *in);
    static void* start_recv(void *arg);
    static void* start_send(void *arg);
    static void set_cpu(void);
    static void drop_privs();
    static void split_string(char* in, int *len, char***results);
    char* strncat(char *dest, const char *src, size_t n);

		void Config(v8::Handle<v8::Object> obj);
		void ConfigLoglevel(v8::Handle<v8::Object> obj);
		void ConfigIface(v8::Handle<v8::Object> obj);
		void ConfigIpaddr(v8::Handle<v8::Object> obj);
		void ConfigHwaddr(v8::Handle<v8::Object> obj);
		void ConfigRange(v8::Handle<v8::Object> obj);
		void ConfigBlacklist(v8::Handle<v8::Object> obj);
		void ConfigWhitelist(v8::Handle<v8::Object> obj);
		void ConfigShards(v8::Handle<v8::Object> obj);
		void ConfigShardTotal(v8::Handle<v8::Object> obj);
		void ConfigProbeModule(v8::Handle<v8::Object> obj);
		void ConfigOutputModule(v8::Handle<v8::Object> obj);
    void ConfigBandwidth(v8::Handle<v8::Object> obj);
    void ConfigThreads(v8::Handle<v8::Object> obj);
		void ConfigWhiteBlackLists(void);
		void ConfigTargets(void);
		void ConfigCores(void);
		void ConfigSeed(void);

    void Threads(void);

    v8::Handle<v8::Value> Summary(void);
		static v8::Handle<v8::Value> LibMasscan(const v8::Arguments& args);

	private:

};

#endif
