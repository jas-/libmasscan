#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

extern "C" {

}

using namespace node;
using namespace v8;

pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;

void libmasscan::Threads(void) {
	libzmap lz;
	iterator_t *it = send_init();

	if (zconf.output_module && zconf.output_module->init) {
		zconf.output_module->init(&zconf, zconf.output_fields,
															zconf.output_fields_len);
	}

	if (!it) {
		ThrowException(Exception::TypeError(
			String::New("Unable to initialize sending component")));
	}

	if (zconf.output_module && zconf.output_module->start) {
		zconf.output_module->start(&zconf, &zsend, &zrecv);
	}

	pthread_t *tsend, trecv;
	int r = pthread_create(&trecv, NULL, start_recv, NULL);
	if (r != 0) {
		ThrowException(Exception::TypeError(
			String::New("Unable to initialize recieving component")));
	}
	for (;;) {
		pthread_mutex_lock(&recv_ready_mutex);
		if (zconf.recv_ready) {
			pthread_mutex_unlock(&recv_ready_mutex);
			break;
		}
		pthread_mutex_unlock(&recv_ready_mutex);
	}

	tsend = (pthread_t*) xmalloc(zconf.senders * sizeof(pthread_t));
	for (uint8_t i = 0; i < zconf.senders; i++) {
		int sock;
		if (zconf.dryrun) {
			sock = get_dryrun_socket();
		} else {
			sock = get_socket();
		}

		send_arg_t *arg = (send_arg_t*) xmalloc(sizeof(send_arg_t));
		arg->sock = sock;
		arg->shard = get_shard(it, i);
		int r = pthread_create(&tsend[i], NULL, start_send, arg);
		if (r != 0) {
			ThrowException(Exception::TypeError(
				String::New("Unable to create send thread")));
		}
	}

	lz.drop_privs();

	for (uint8_t i = 0; i < zconf.senders; i++) {
		int r = pthread_join(tsend[i], NULL);
		if (r != 0) {
			ThrowException(Exception::TypeError(
				String::New("Unable to join send thread")));
		}
	}

	r = pthread_join(trecv, NULL);
	if (r != 0) {
		ThrowException(Exception::TypeError(
			String::New("Unable to join receive threads")));
	}

	if (zconf.output_module && zconf.output_module->close) {
		zconf.output_module->close(&zconf, &zsend, &zrecv);
	}

	if (zconf.probe_module && zconf.probe_module->close) {
		zconf.probe_module->close(&zconf, &zsend, &zrecv);
	}
}

void* libmasscan::start_send(void *arg) {
	send_arg_t *v = (send_arg_t *) arg;
	set_cpu();
	send_run(v->sock, v->shard);
	free(v);
	return NULL;
}

void* libmasscan::start_recv(void *arg) {
	set_cpu();
	recv_run(&recv_ready_mutex);
	return NULL;
}
