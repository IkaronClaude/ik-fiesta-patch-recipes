// dbhook.h - running SQL from a Character.exe hook, on the connection the server already has.
//
// A plugin never opens its own database connection. Every worker thread owns an already-connected
// DBRecord (CSessionWorker::m_DBF, at kWorkerDbfOffset - read off all 33 of the server's own query sites),
// and the server's stored-procedure wrappers (CSQLPCharacter::usp_* and friends) do nothing more than
// format a query on it, execute it and fetch. So does this:
//
//     CHAR_HOOK_HANDLER(fc_NC_CHARSAVE_ALL_REQ, {
//         int result = CHAR_CALL_ORIGINAL_OF(fc_NC_CHARSAVE_ALL_REQ);    // the server's own work first
//         chr::db::Query q(chr::db::of_handler(self), "EXEC dbo.usp_VoidInven_Save %d, %d", charNo, page);
//         while (q.ok() && q.next()) { int v = q.read_int(); ... }
//         return result;                                                 // ~Query closes the cursor
//     });
//
// PLUGINS ONLY. This uses vsnprintf, so it needs the CRT, which hooks/*.dll have and the loader does not.
//
// THREE RULES, each from reading the server's own DBRecord::query (Account.pdb, same framework):
//
//   1. ONE STATEMENT PER WORKER. query() starts with SQLCloseCursor + SQLFreeStmt(SQL_CLOSE) on the worker's
//      only statement handle. Run a query while the ORIGINAL handler is part-way through its own fetch loop
//      and you close its cursor under it. So: run yours before calling the original, or after it returns -
//      never from a hook on something the original calls in the middle of its fetch.
//   2. THE SERVER'S FORMAT BUFFER IS 8 KB AND UNCHECKED. query() vsprintf()s into 0x2004 bytes of stack with
//      no length limit. This wrapper formats with a bounded vsnprintf first, refuses anything that does not
//      fit, and hands the server the finished text through "%s" - so nothing in it can be read as a format
//      specifier either.
//   3. IT IS THE WORKER'S CONNECTION, NOT YOURS. Use it only from a handler running on that worker, via the
//      handler's own `self`. A second thread touching it races the server's own queries.
//
// Values interpolated into SQL text are YOUR responsibility: format integers, never raw strings from a
// packet. For strings and binary (item attribute blobs), bind them as parameters through ODBC directly -
// odbc() below returns any ODBC32 entry point, and statement() the handle to use it on.
#pragma once
#include <stdarg.h>
#include <stdio.h>
#include "charhook.h"

namespace chr {
namespace db {

// DBRecord, as Account.pdb lays it out: its Database base { vtable, bool m_bTran, void* handleDBC } and then
// void* handleStatement @12, int columnNo @16. Opaque here - use the functions.
struct Record;

// The worker's DBRecord, from a handler's `self`.
inline Record* of_handler(void* self) {
    void* w = worker_of(self);
    return w ? (Record*)((char*)w + kWorkerDbfOffset) : NULL;
}

namespace detail {
// The framework functions come from character_symbols.h as typed chr::fn::X() accessors; one the byte match
// could not find in this exe has no accessor at all, so using it is a compile error, not a null call.

// The size the server's own buffer can hold, less the terminator. See rule 2.
enum { kMaxQuery = 0x2004 - 1 };
}  // namespace detail

// Execute SQL on the worker's statement. printf-style, bounded. true on SQL_SUCCESS / SQL_SUCCESS_WITH_INFO.
inline bool query(Record* rec, const char* fmt, ...) {
    if (!rec || !fmt) return false;
    char sql[detail::kMaxQuery + 1];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(sql, sizeof(sql), fmt, ap);
    va_end(ap);
    if (n < 0 || n > detail::kMaxQuery) {
        log("[db] REFUSED: query longer than the server's %d-byte buffer (%d)", (int)detail::kMaxQuery, n);
        return false;
    }
    bool ok = fn::DBRecord_query()(rec, (char*)"%s", sql);
    if (!ok) log("[db] query FAILED: %s", sql);
    return ok;
}

// Next row. false at the end of the result set.
inline bool fetch(Record* rec) {
    return rec && fn::DBRecord_fetch()(rec, 0);
}

// Close the cursor. Always, before anything else uses the statement - see rule 1.
inline void end_fetch(Record* rec) {
    if (rec) fn::DBRecord_endFetch()(rec, 0);
}

// The next column of the current row, in order. The framework has exactly these two readers.
inline int read_int(Record* rec) {
    int v = 0;
    if (rec) fn::DBRecord_readInt()(rec, 0, &v);
    return v;
}

inline unsigned long read_ulong(Record* rec) {
    unsigned long v = 0;
    if (rec) fn::DBRecord_readULong()(rec, 0, &v);
    return v;
}

// The worker's ODBC statement handle (HSTMT), for everything the two readers cannot do.
inline void* statement(Record* rec) {
    return rec ? fn::DBRecord_getStatement()(rec, 0) : NULL;
}

// Commit, on the worker's connection (Database::CommitTran).
inline bool commit(Record* rec) {
    return rec && fn::Database_CommitTran()(rec, 0);
}

// Any ODBC32 entry point, by NAME. Character.exe imports ODBC32 only by ordinal, so its IAT has no names to
// hook or look up - but odbc32.dll exports every function by name, and it is already loaded.
//     auto SQLGetData = (SQLRETURN(SQL_API*)(SQLHSTMT, ...))chr::db::odbc("SQLGetData");
inline void* odbc(const char* name) {
    HMODULE m = GetModuleHandleA("odbc32.dll");
    return m ? (void*)GetProcAddress(m, name) : NULL;
}

// One query and its cursor. The destructor ALWAYS closes the cursor, so an early return from a handler
// cannot leave the worker's only statement open for the server's next query to trip over.
class Query {
public:
    Query(Record* rec, const char* fmt, ...) : rec_(rec), ok_(false) {
        if (!rec || !fmt) return;
        char sql[detail::kMaxQuery + 1];
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(sql, sizeof(sql), fmt, ap);
        va_end(ap);
        if (n < 0 || n > detail::kMaxQuery) {
            log("[db] REFUSED: query longer than the server's %d-byte buffer (%d)", (int)detail::kMaxQuery, n);
            return;
        }
        ok_ = query(rec, "%s", sql);
    }
    ~Query() { if (rec_) end_fetch(rec_); }
    Query(const Query&) = delete;
    Query& operator=(const Query&) = delete;

    bool ok() const { return ok_; }
    bool next() { return ok_ && fetch(rec_); }
    int read_int() { return db::read_int(rec_); }
    unsigned long read_ulong() { return db::read_ulong(rec_); }

private:
    Record* rec_;
    bool ok_;
};

}  // namespace db
}  // namespace chr
