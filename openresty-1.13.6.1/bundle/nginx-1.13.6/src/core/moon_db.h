#ifndef __MOON_H__
#define __MOON_H__

#include <king_mysql/king_mysql.h>

enum moon_db_err
{
    MOON_DB_OK = 0,
    MOON_DB_ERR = 1,
    MOON_DB_NO_LINE
};

typedef struct moon_db_info_s
{
    int init_flag;
    king_mysql_t info;
} moon_db_info_t;

extern moon_db_info_t g_db_conn;

typedef struct moon_accout_s
{
    long id;
    char name[32];
    long last_login_ts;
    long reg_ts;
} moon_account_t;

int test_mysql(int a, int b, ngx_log_t *log);

int moon_db_init_internal(ngx_log_t *log);

int moon_db_init(ngx_log_t *log, char *host, int port, char *user, char *passwd,
        char *db_name);

int moon_db_account_update(ngx_log_t *log, char *db_name,
        moon_account_t *account);

int moon_db_account_query(ngx_log_t *log, char *db_name, moon_account_t *account);

int moon_db_account_add(ngx_log_t *log, char *db_name, moon_account_t *account);

#endif
