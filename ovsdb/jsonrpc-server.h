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
#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "trigger.h"
#include "server.h"

struct ovsdb;
struct shash;
struct simap;
struct stream;
struct ovs_list;
struct ovsdb_jsonrpc_remote;
struct sessions_handler;
struct ds;

DECLARE_EXTERN_PER_THREAD_DATA(struct sessions_handler *, thread_handler);

/* Return a per-thread sessions_handler pointer. This value is assigned once
 * when a thread is craeted, and never changes within the lifetime of the
 * process.  */
static inline struct sessions_handler *
ovsdb_thread_sessions_handler(void)
{
    return *thread_handler_get();
}

/* JSON-RPC database server. */
struct ovsdb_jsonrpc_server {
    struct ovsdb_server up;
    atomic_count n_sessions;
    struct shash remotes;      /* Contains "struct ovsdb_jsonrpc_remote *"s. */

    /* Handlers a set of 'ovsdb_jsonrpc_sessions'.
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

    /* Threads. */
    /* No need to store 'n_max_threads' here, it can be derived from
     * 'n_handlers'.  */
    unsigned int n_handlers;     /* n_max_threads = n_handlers - 1. */
};

struct ovsdb_jsonrpc_server *ovsdb_jsonrpc_server_create(size_t n_max_threads);
bool ovsdb_jsonrpc_server_add_db(struct ovsdb_jsonrpc_server *,
                                 struct ovsdb *);
bool ovsdb_jsonrpc_server_remove_db(struct ovsdb_jsonrpc_server *,
                                     struct ovsdb *);
void ovsdb_jsonrpc_server_destroy(struct ovsdb_jsonrpc_server *);
void ovsdb_jsonrpc_server_lock(struct ovsdb_jsonrpc_server *svr)
    OVS_ACQUIRES(svr->up.mutex);
void ovsdb_jsonrpc_server_unlock(struct ovsdb_jsonrpc_server *svr)
    OVS_RELEASES(svr->up.mutex);

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

void ovsdb_jsonrpc_server_create_session(
    struct ovsdb_jsonrpc_server *svr,
    struct stream *stream,
    struct ovsdb_jsonrpc_remote *remote);


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

    /* Data base server global lock, protects access to
     * 'ovsdb_lock' */
    struct ovs_mutex mutex;
};

bool ovsdb_jsonrpc_server_get_remote_status(
    const struct ovsdb_jsonrpc_server *, const char *target,
    struct ovsdb_jsonrpc_remote_status *);
void ovsdb_jsonrpc_server_free_remote_status(
    struct ovsdb_jsonrpc_remote_status *);

void ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *);
void ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *);
void ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *);
size_t  ovsdb_jsonrpc_server_sessions_count(
    struct ovsdb_jsonrpc_server *, struct ovsdb_jsonrpc_remote *);

struct ovsdb_jsonrpc_session *ovsdb_jsonrpc_server_first_session(
    struct ovsdb_jsonrpc_server *, struct ovsdb_jsonrpc_remote *);

void ovsdb_jsonrpc_server_get_memory_usage(struct ovsdb_jsonrpc_server *,
                                           struct simap *usage);
void ovsdb_jsonrpc_server_trigger_completed(struct ovs_list *);

void ovsdb_jsonrpc_server_add_session(struct ovsdb_jsonrpc_server *,
                                      struct stream *,
                                      struct ovsdb_jsonrpc_remote *,
                                      uint8_t dscp);
void ovsdb_jsonrpc_server_get_threads_info(struct ds *ds,
                                           struct ovsdb_jsonrpc_server *);

void ovsdb_jsonrpc_server_add_trigger(struct ovsdb_jsonrpc_server *,
                                      struct ovsdb_trigger *);
void ovsdb_jsonrpc_server_remove_trigger(struct ovsdb_jsonrpc_server *,
                                          struct ovsdb_trigger *);

/* IPC messages are used to communicate between the main thread and
 * jsonrpc sessions thread.
 *
 * There are three styles of IPC messages.
 *  * Global Sync.  All threads will be stopped at a barrier,
 *  except the main handler. Main handler can safly access (read)
 *  per thread private data, then release the barrier. There is
 *  only one message of this type, OVSDB_IPC_SYNC.
 *
 *  * Message without sync. A thread sends a message to another
 *  thread without waiting for confirmation that the message
 *  has been executed. This style of messages reduces the head of
 *  line blocking for the calling threads of handling the next event.
 *
 * * Message with sync. The caller should be blocked until the
 *   message has been exectued on target thread(s). This style of messages
 *   ensures that the access to shared objects (by message handlers) has
 *   finished.
 *
 * Summary of Messages:
 *
 *  message                SYNC                Usage
 *  =======                =====          ===============================
 * OVSDB_IPC_SYNC          global         main handler -> other handlers
 * OVSDB_IPC_NEW_SESSION    no            main handler -> other handlers
 * OVSDB_IPC_CLOSE_SESSIONS yes           main handler -> other handlers
 * OVSDB_IPC_RECONNET       yes           main handler -> other handlers
 *
 * Implementation Details:
 *
 * - OVSDB_IPC_SYNC
 * This is generic thread synchronization mechanism that uses
 * two ovs_barriers. A 'stop' barrier is used to make sure
 * all handlers threads have reached this barrier before the
 * main handler can safely operate on per thread data structure,
 * such as access the sessions list, while all threads spins
 * on the 'go' barrier, until the main thread is done
 * and releases the 'go' barrier.
 *
 * Note, we don't use this message to change the life cycle of individual
 * session, following the principle that a session is only created and
 * destroyed in a single handler.
 *
 * - OVSDB_IPC_NEW_SESSION
 * Create a new jsonrpc session for a given 'stream'.
 *
 * - OVSDB_IPC_CLOSE_SESSIONS
 * Delete all sessions associated with the 'remote'.
 *
 * - OVSDB_IPC_RECONNET
 * Reconnect all sessions associated with a given 'remote'.
 *
 * - OVSDB_IPC_SET_OPTIONS
 * Reset options of all sessions associated with a given 'remote'.
 */
#define OVSDB_IPC_MESSAGES \
       OVSDB_IPC_MESSAGE(SYNC) \
       OVSDB_IPC_MESSAGE(NEW_SESSION) \
       OVSDB_IPC_MESSAGE(CLOSE_SESSIONS) \
       OVSDB_IPC_MESSAGE(RECONNECT) \
       OVSDB_IPC_MESSAGE(SET_OPTIONS) \
       OVSDB_IPC_MESSAGE(LOCK_NOTIFY) \
       OVSDB_IPC_MESSAGE(TRIGGER) \
       OVSDB_IPC_MESSAGE(MONITOR)

enum ovsdb_ipc_type {
#define OVSDB_IPC_MESSAGE(MSG) OVSDB_IPC_##MSG,
    OVSDB_IPC_MESSAGES
#undef OVSDB_IPC_MESSAGE
    OVSDB_IPC_N_MESSAGES,
};

/* Generic IPC data structure. This data structure should be embedded in
 * the definition of specific messages.  */
struct ovsdb_ipc {
    struct ovs_list list;      /* List node in sessions_handler's ipc_queue. */
    size_t size;
    enum ovsdb_ipc_type message;
};

void ovsdb_ipc_init(struct ovsdb_ipc *ipc, enum ovsdb_ipc_type message,
                    size_t size);

struct ovsdb_ipc *
ovsdb_ipc_lock_notify_create(struct ovsdb_jsonrpc_session *session,
                             const char *lock_name);

enum ovsdb_ipc_trigger_subtype {
     OVSDB_IPC_TRIGGER_ADD,
     OVSDB_IPC_TRIGGER_REMOVE,
     OVSDB_IPC_TRIGGER_COMPLETED
};

enum ovsdb_ipc_monitor_subtype {
     OVSDB_IPC_MONITOR_SERVER_ADD,
     OVSDB_IPC_MONITOR_SERVER_REMOVE,
     OVSDB_IPC_MONITOR_SESSION_ADD,
     OVSDB_IPC_MONITOR_SESSION_REMOVE
};

struct ovsdb_jsonrpc_monitor;
struct ovsdb_ipc *
ovsdb_ipc_monitor_create(enum ovsdb_ipc_monitor_subtype subtype,
                         struct ovsdb_jsonrpc_monitor *jsonrpc_monitor);

void ovsdb_ipc_sendto(struct sessions_handler *handler, struct ovsdb_ipc *ipc);

#endif /* OVSDB_JSONRPC_SERVER_H */

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
 * Locks and Lock waiters:
 *      Locks can be created by a session from any thread, To ensure
 *      lock uniqueness, a global database lock is required for creating
 *      and destroy locks.
 *
 *      Access to locks are only allowed by the thread that owns the lock.
 *
 *      'Owning a lock' is defined by a waiter that are currently granted
 *      the lock.
 *
 *      Each session can have lock waiter (i.e. ovsdb_jsonrpc_lock_waiter)
 *      structure for a lock. The lock waiter structure is created and
 *      managed by each thread privately.  Each session accesses locks via
 *      the corresponding lock waiter.  When a lock is 'unlocked',
 *      the 'unlocking' session should inform the next 'waiter'
 *      session on the lock via IPC message, in case the 'waiter' is not
 *      running on the same thread. Waiter structure needs to be reference
 *      counted. A locker without any waiter are destroyed.
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
 *    L  -- lock  (annotate with the lock required)
 *
 * Additional annotation:
 *  L:   PO -- per object lock
 *       or the name of a global lock.
 *
 *  LF:  Access will be restricted to a particular thread
 *       MT:  the main thread.
 *       ST:  sessions thread.
 *
 * Object     Life cycle      Access           Ref count pointer
 * =======================================================================
 * Remote     LF (MT)         LF (MT)          Yes
 * Session    LF (ST)         LF (ST)          Yes
 * Monitor    LF (MT)         L  (PO)          Yes
 * Lock       L  (ovsdb)      LF (ST)          NO
 * Waiter     LF (ST)         LF (ST)          YES
 * Trigger    LF (MT)         L  (PO)          Yes
 * DB         LF (MT)         L  (PO)          NO
 */
