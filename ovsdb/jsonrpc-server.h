/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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

#ifndef OVSDB_JSONRPC_SERVER_H
#define OVSDB_JSONRPC_SERVER_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/types.h"
#include "server.h"

struct ovsdb;
struct shash;
struct simap;
struct stream;
struct ovs_list;
struct ovsdb_jsonrpc_remote;
struct sessions_handler;

/* JSON-RPC database server. */
struct ovsdb_jsonrpc_server {
    struct ovsdb_server up;
    unsigned int n_sessions;
    struct shash remotes;      /* Contains "struct ovsdb_jsonrpc_remote *"s. */

    /* Handlers for 'ovs_list' that contains 'ovsdb_jsonrpc_sessions'.
     *
     * Each 'handler' handles a set of ovdb_jsonrpc_sessions.
     * When OVSDB runs in a multi-threaded environment, there will be
     * exactly 'n + 1' handlers for 'n' threads.  Each thread owns
     * one handler, plus the main handler owned by the main process.
     * the main process's handler is called the 'main handler'.
     *
     * The 'main handler' is always the first handler of the array.
     *
     * The handlers are statically allocated for the server; they
     * are crated when ovsdb_jsonrpc_server is crated.  Once created,
     * both 'n_handlers' and 'handlers' are never changed or moved until
     * the server is destroyed.    */
    struct sessions_handler *handlers;
    unsigned int n_handlers;

    /* Threads. */
    /* No need to store 'n_max_threads' here, it can be derived from
     * 'n_handlers', n_max_threads == n_handlers - 1.  */
    size_t n_active_threads;
};

struct ovsdb_jsonrpc_server *ovsdb_jsonrpc_server_create(size_t n_max_threads);
bool ovsdb_jsonrpc_server_add_db(struct ovsdb_jsonrpc_server *,
                                 struct ovsdb *);
bool ovsdb_jsonrpc_server_remove_db(struct ovsdb_jsonrpc_server *,
                                     struct ovsdb *);
void ovsdb_jsonrpc_server_destroy(struct ovsdb_jsonrpc_server *);

/* Options for a remote. */
struct ovsdb_jsonrpc_options {
    int max_backoff;            /* Maximum reconnection backoff, in msec. */
    int probe_interval;         /* Max idle time before probing, in msec. */
    int dscp;                   /* DSCP value for manager connections */
};
struct ovsdb_jsonrpc_options *
ovsdb_jsonrpc_default_options(const char *target);

void ovsdb_jsonrpc_server_set_remotes(struct ovsdb_jsonrpc_server *,
                                      const struct shash *);

/* Status of a single remote connection. */
struct ovsdb_jsonrpc_remote_status {
    const char *state;
    int last_error;
    unsigned int sec_since_connect;
    unsigned int sec_since_disconnect;
    bool is_connected;
    char *locks_held;
    char *locks_waiting;
    char *locks_lost;
    int n_connections;
    ovs_be16 bound_port;
};

bool ovsdb_jsonrpc_server_get_remote_status(
    const struct ovsdb_jsonrpc_server *, const char *target,
    struct ovsdb_jsonrpc_remote_status *);
void ovsdb_jsonrpc_server_free_remote_status(
    struct ovsdb_jsonrpc_remote_status *);

void ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *);

void ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *);
void ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *);
size_t ovsdb_jsonrpc_server_sessions_count(
    struct ovsdb_jsonrpc_server *, struct ovsdb_jsonrpc_remote *);

struct ovsdb_jsonrpc_session *ovsdb_jsonrpc_server_first_session(
    const struct ovsdb_jsonrpc_server *, const struct ovsdb_jsonrpc_remote *);

void ovsdb_jsonrpc_server_get_memory_usage(const struct ovsdb_jsonrpc_server *,
                                           struct simap *usage);

void ovsdb_jsonrpc_server_add_session(struct ovsdb_jsonrpc_server *,
                                      struct stream *,
                                      struct ovsdb_jsonrpc_remote *,
                                      uint8_t dscp);

/* OVSDB server Multi-Threading design
 * ==================================
 *
 * Number of threads
 * =================
 * OVSDB server start 'n' pthreads to scale up the handling of jsonrpc
 * sessions. The 'n' whatever user specifies as the 'max_threads' parameter
 * ovsdb-server receives on the command line.
 *
 * Session to thread assignment
 * ============================
 * Currently it is randomly assigned for simplicity. (We can change to
 * assigning based on load if that is more useful). Once assigned, the
 * sessions will always be handled by the same thread.
 *
 * Using Messages between threads (IPC)
 * ====================================
 * Each thread can send and receive IPC messages to and from another thread.
 * There are two benefits of using IPC messages. Using IPC messages lessen
 * the requirement for each object to be thread safe, by funneling operations
 * of an object into a single thread.  More importantly, IPC messages are
 * asynchronous; the sending thread can continue processing without waiting
 * for the work to be done.
 *
 * Thread safety consideration for OVSDB objects
 * =============================================
 * Life Cycle:
 *      If an object is always created and destroyed by a single thread, then
 *      its membership in a group (e.g. in a linked list) can be managed
 *      lock free. On the other hand, synchronization is required and
 *      should be documented.
 *
 *      Note, in case of Opaque pointer, the physical memory of the object
 *      can freed by another thread. But this does not change the
 *      synchronization requirement of object destruction.
 *
 * Access:
 *      If an object is always accessed by a single thread, it can be
 *      accessed lock-free. Otherwise, synchronization is required
 *      and documented below.
 *
 * Opaque Pointer:
 *      Besides access to an object, a thread can also hold an opaque
 *      pointer for the purposes of identifying an object (i.e. to match
 *      an object by matching the pointer value), or use it inside an
 *      IPC messages in order to communicate with another thread.
 *
 *      As long as opaque pointer exists, the memory of this object needs
 *      to be occupied to prevent OS from minting another object with
 *      the same address.  Reference counting is an well understood
 *      technique that prevents dangling pointers. OVSDB threads
 *      implementation uses 'struct ovs_refcount' for all objects that
 *      may hand out opaque pointers.
 *
 * Details:
 * -------
 * Remote:
 *      Remotes is always created, destroyed by the main process, and
 *      can be accessed by the main process lock free.  It can hand out
 *      opaque pointers to be embedded in 'Sessions' and in IPC thus
 *      should be reference counted.
 *
 * Sessions:
 *      Sessions are always created and destroyed and accessed by the
 *      same thread. These access are lock free. Sessions can be passed
 *      into OVSDB locks as opaque pointers.
 *
 * Locks:
 *      Locks can be created by a session from any thread, To ensure
 *      lock uniqueness, a global database lock is required for creating
 *      and destroy locks. Access to locks require the same lock.
 *
 *      Each session holds a lock waiter (i.e. ovsdb_jsonrpc_lock_waiter)
 *      structure. The lock waiter structure is created and managed by
 *      each thread. The pointer to a lock waiter valid if and only if
 *      its associated session is valid.  Thus pointers to lock waiter
 *      does not need to be reference counted.
 *
 *      Each session accesses lock via the lock waiter.  When a lock is
 *      'unlocked', the 'unlocking' session should inform the next 'waiter'
 *      session on the lock via IPC message, in case the 'waiter' is not
 *      running on the same thread.
 *
 * Monitor:
 *      Monitors are always created and destroyed by the main process.
 *      Sessions send IPC message to the main process to create or
 *      destroy them.  Main process responds to monitor creation IPC
 *      with a pointer to the monitor, which can be shared with other
 *      sessions.
 *
 *      Access to monitor requires per monitor lock, since both the main
 *      process and sessions can access monitor concurrently.
 *      An Opaque pointer can be embedded in an IPC message, thus needs to
 *      be reference counted.
 *
 * Trigger:
 *      Triggers are always created and destroyed by the main process.
 *      Sessions send IPC message to the main process to create or destroy
 *      them. Access to them requires per trigger lock.
 *
 * Summary:
 * --------
 *
 * Notation:
 *    LF -- lock free
 *    L  -- lock
 *
 * Object     Life cycle      Access           Ref count pointer
 * =======================================================================
 * Remote     LF              LF               Yes
 * Session    LF              LF               Yes
 * Monitor    LF              L                Yes
 * Lock       LF              L                No
 * trigger    LF              L                Yes
 * */
#endif /* ovsdb/jsonrpc-server.h */
