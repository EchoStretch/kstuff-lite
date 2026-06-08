#include <stddef.h>
#include <sys/mman.h>
#include <sqlite3.h>


struct buf
{
    char* data;
    size_t sz;
    size_t cap;
};

#define SQL_COMMANDS_PER_TABLE(PUTS, PUTN)\
PUTS("create trigger if not exists trig_update_drm_") PUTN() PUTS(" after update of appDrmType on ") PUTN() PUTS(" when new.appDrmType = 1 begin update ") PUTN() PUTS(" set appDrmType = 5 where titleId = old.titleId; end;")\
PUTS("create trigger if not exists trig_insert_drm_") PUTN() PUTS(" after insert on ") PUTN() PUTS(" when new.appDrmType = 1 begin update ") PUTN() PUTS(" set appDrmType = 5 where titleId = new.titleId; end;")\
PUTS("update ") PUTN() PUTS(" set appDrmType=5 where appDrmType=1;")

void log_table_name(struct buf* buf, const unsigned char* name)
{
    char* prefix = "tbl_iconinfo_";
    size_t i = 0;
    while(prefix[i] && prefix[i] == name[i])
        i++;
    if(!prefix[i])
    {
        while(name[i])
            i++;
#define PUTS(s) +(sizeof(s) - 1)
#define PUTN() +i
        size_t new_sz = buf->sz SQL_COMMANDS_PER_TABLE(PUTS, PUTN);
#undef PUTN
#undef PUTS
        size_t cap = buf->cap;
        if(cap < 16384)
            cap = 16384;
        if(new_sz > cap)
            cap *= 2;
        if(new_sz > cap)
            cap = new_sz;
        if(cap != buf->cap)
        {
            char* new_data = mmap(0, cap, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            char* data = buf->data;
            size_t sz = buf->sz;
            for(size_t i = 0; i < sz; i++)
                new_data[i] = data[i];
            munmap(data, buf->cap);
            buf->data = new_data;
            buf->cap = cap;
        }
#define PUT(s, l)\
        for(size_t j = 0; j < l; j++)\
            buf->data[buf->sz++] = s[j];
#define PUTS(s) PUT(s, sizeof(s)-1)
#define PUTN() PUT(name, i)
        SQL_COMMANDS_PER_TABLE(PUTS, PUTN)
#undef PUTN
#undef PUTS
#undef PUT
    }
}

//sqlite3_exec
void run_stmt(sqlite3* db, const char* cmd, struct buf* buf)
{
    while(*cmd)
    {
        sqlite3_stmt* stmt;
        const char* tail;

        if(sqlite3_prepare_v2(db, cmd, -1, &stmt, &tail) != SQLITE_OK)
            asm volatile("ud2");
        cmd = tail;
        int status;
        while((status = sqlite3_step(stmt)) == SQLITE_ROW)
            if(buf)
                log_table_name(buf, sqlite3_column_text(stmt, 0));
        if(status != SQLITE_DONE)
            asm volatile("ud2");
        sqlite3_finalize(stmt);
    }
}

int patch_app_db(void)
{
    struct buf buf = {};
    sqlite3* db;
    char* cmd;

    if(sqlite3_open_v2("/system_data/priv/mms/app.db", &db, SQLITE_OPEN_READWRITE, 0) != SQLITE_OK)
        return -1;

    run_stmt(db, "select tbl_name from sqlite_master where type = 'table';", &buf);
    cmd = buf.data;
    if(buf.sz == buf.cap)
    {
        cmd = mmap(0, buf.cap+16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        for(size_t i = 0; i < buf.sz; i++)
            cmd[i] = buf.data[i];
    }
    run_stmt(db, cmd, 0);

    if(buf.sz == buf.cap)
        munmap(cmd, buf.cap+16384);

    munmap(buf.data, buf.cap);

    return 0;
}
