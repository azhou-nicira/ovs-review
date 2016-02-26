/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include "jsonrpc.h"
#include "jsonrpc-remote.h"
#include "jsonrpc-server.h"
#include "openvswitch/vlog.h"
#include "reconnect.h"
#include "simap.h"
#include "stream.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_jsonrpc_remote);

/* Message rate-limiting. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* A configured remote.  This is either a passive stream listener plus a list
 * of the currently connected sessions, or a list of exactly one active
 * session.
 *
 * This definition only provided here because the functions below needs to
 * access it. Functions above this definition treat ovsdb_jsonrpc_remote as
 * an opaque type.  */
struct ovsdb_jsonrpc_remote {
    struct ovsdb_jsonrpc_server *server;
    struct pstream *listener;   /* Listener, if passive. */
    uint8_t dscp;
};

struct ovsdb_jsonrpc_remote *
ovsdb_jsonrpc_remote_create(struct ovsdb_jsonrpc_server *svr,
                            const char *name,
                            const struct ovsdb_jsonrpc_options *options,
                            struct pstream **listener)
{
    struct ovsdb_jsonrpc_remote *remote;
    int error;

    error = jsonrpc_pstream_open(name, listener, options->dscp);
    if (error && error != EAFNOSUPPORT) {
        VLOG_ERR_RL(&rl, "%s: listen failed: %s", name, ovs_strerror(error));
        return NULL;
    }

    remote = xmalloc(sizeof *remote);
    remote->server = svr;
    remote->listener = *listener;
    remote->dscp = options->dscp;

    return remote;
}

void
ovsdb_jsonrpc_remote_destroy(struct ovsdb_jsonrpc_remote *remote)
{
    pstream_close(remote->listener);
}

bool
ovsdb_jsonrpc_remote_get_status(struct ovsdb_jsonrpc_remote *remote,
                                struct ovsdb_jsonrpc_remote_status *status)
{
    if (remote->listener) {
        int n_connections = ovsdb_jsonrpc_server_sessions_count(remote->server,
                                                                remote);

        status->bound_port = pstream_get_bound_port(remote->listener);
        status->n_connections = n_connections;
        status->is_connected = (n_connections != 0);
        return true;
    }

    struct ovsdb_jsonrpc_session *s;
    size_t c = ovsdb_jsonrpc_server_sessions_count(remote->server, remote);
    if (!c) {
        return false;
    }

    s = ovsdb_jsonrpc_server_first_session(remote->server, remote);
    ovs_assert(s);
    ovsdb_jsonrpc_session_get_status(s, status);
    status->n_connections = 1;

    return true;
}

void
ovsdb_jsonrpc_remote_run(struct ovsdb_jsonrpc_remote *remote)
{
    if (remote->listener) {
        struct stream *stream;
        int error;

        error = pstream_accept(remote->listener, &stream);
        if (!error) {
            struct jsonrpc_session *js;
            js = jsonrpc_session_open_unreliably(jsonrpc_open(stream),
                                                 remote->dscp);
            ovsdb_jsonrpc_session_create(remote->server, js, remote);
        } else if (error != EAGAIN) {
            VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                         pstream_get_name(remote->listener),
                         ovs_strerror(error));
        }
    }
}

void
ovsdb_jsonrpc_remote_wait(struct ovsdb_jsonrpc_remote *remote)
{
    if (remote->listener) {
        pstream_wait(remote->listener);
    }
}


struct ovsdb_jsonrpc_server *
ovsdb_jsonrpc_remote_get_server(struct ovsdb_jsonrpc_remote *remote)
{
    return remote->server;
}

/* Returns 'true' if remote can be update to 'new_options' without
 * shutdown the existing connection first.  'false' otherwise.  */
bool
ovsdb_jsonrpc_remote_options_can_change(
    const struct ovsdb_jsonrpc_remote *remote,
    const struct ovsdb_jsonrpc_options *new_options)
{
    return (remote->dscp == new_options->dscp);
}

