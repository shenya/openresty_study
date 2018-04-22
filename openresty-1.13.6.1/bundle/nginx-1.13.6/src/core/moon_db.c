#include <stdio.h>
#include <string.h>

#include <ngx_core.h>

#include <moon_db.h>

#include <king_mysql/king_mysql.h>

char *host = "localhost";
char *user = "root";
char *passwd = "sgy2017";
char *db = "my_ngx";
int port = 3306;

moon_db_info_t g_db_conn;

int moon_db_init_internal(ngx_log_t *log)
{
    int ret = MOON_DB_OK;

    ret = king_mysql_init(&(g_db_conn.info), host, port, user, passwd, db);
    if (0 != ret)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                "ngx mysql init failed");
        return MOON_DB_ERR;
    }

    ngx_log_error(NGX_LOG_EMERG, log, 0,
                   "ngx mysql init success");

    g_db_conn.init_flag = 1;

    return ret;
}

int moon_db_init(ngx_log_t *log, char *host, int port, char *user, char *passwd,
        char *db_name)
{
    int ret = MOON_DB_OK;

    ret = king_mysql_init(&(g_db_conn.info), host, port, user, passwd, db_name);
    if (0 != ret)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                "ngx mysql init failed");
        return MOON_DB_ERR;
    }

    g_db_conn.init_flag = 1;

    return ret;
}

int moon_db_account_add(ngx_log_t *log, char *db_name, moon_account_t *account)
{
    int ret = KING_DB_OK;
    char sql_buf[1024] = {0};
    long out_id = 0;

    snprintf(sql_buf, sizeof(sql_buf), "insert into ngx_account(name, last_login_ts, reg_ts) "\
            "values('%s', '%ld', '%ld')", account->name, account->last_login_ts,
            account->reg_ts);

    ret = king_mysql_extend_add(&g_db_conn.info, db_name, sql_buf,
            strlen(sql_buf), &out_id);
    if (KING_DB_OK != ret)
    {
        ret = MOON_DB_ERR;
        return ret;
    }

    return MOON_DB_OK;
}

int moon_db_account_query(ngx_log_t *log, char *db_name, moon_account_t *account)
{
    int ret = KING_DB_OK;
    char sql_buf[1024] = {0};
    king_result_t result;
    king_element_t *element = NULL;

    memset(&result, 0, sizeof(result));

    snprintf(sql_buf, sizeof(sql_buf), "select id, name, last_login_ts, reg_ts "\
            "from ngx_account where name='%s'",
            account->name);

    ret = king_mysql_query_result(&g_db_conn.info, db_name, &result, sql_buf,
            strlen(sql_buf));
    ngx_log_error(NGX_LOG_EMERG, log, 0,
                   "ngx: db_name: %s, sql_buf: %s: ret:%d", db_name, sql_buf, ret);

    if (KING_DB_OK != ret)
    {
        ret = MOON_DB_ERR;
        return ret;
    }

    if (0 == result.total || 4 != result.total)
    {
        ret = MOON_DB_NO_LINE;
        return ret;
    }

    element = result.result_set;

    account->id = atol(element->s_value);

    element++;

    snprintf(account->name, sizeof(account->name), "%s", element->s_value);
    element++;
    account->last_login_ts = atol(element->s_value);
    element++;
    account->reg_ts = atol(element->s_value);

    king_free_result(&result);

    return MOON_DB_OK;
}

int moon_db_account_update(ngx_log_t *log, char *db_name,
        moon_account_t *account)
{
    int ret = KING_DB_OK;
    char sql_buf[1024] = {0};

    char upd_buf[256] = {0};
    int upd_len = 0;
    int len = 0;

    if (0 != account->last_login_ts)
    {
        upd_len += snprintf(upd_buf + upd_len, sizeof(upd_buf) - upd_len,
                "last_login_ts=%ld,", account->last_login_ts);
    }

    if (0 != account->reg_ts)
    {
        upd_len += snprintf(upd_buf + upd_len, sizeof(upd_buf) - upd_len,
                "reg_ts=%ld,", account->reg_ts);
    }

    if (strlen(upd_buf) > 0)
    {
        upd_buf[strlen(upd_buf) - 1] = '\0';
    }
    else
    {
        return MOON_DB_ERR;
    }

    snprintf(sql_buf, sizeof(sql_buf), "update ngx_account set %s "\
            "where name='%s'",
            upd_buf,
            account->name);

    len = sizeof(sql_buf);
    ret = king_mysql_update(&(g_db_conn.info), db_name, sql_buf,
            len);
    
    if (KING_DB_OK != ret)
    {
        ret = MOON_DB_ERR;
    }

    return MOON_DB_OK;
}

int test_mysql(int a, int b, ngx_log_t *log)
{
    king_mysql_t mysql_info;
    int ret = 0;

    memset(&mysql_info, 0, sizeof(mysql_info));

    ret = king_mysql_init(&mysql_info, host, port, user, passwd, db);
    if (ret < 0)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                "ngx mysql init failed");
    }

    ngx_log_error(NGX_LOG_EMERG, log, 0,
            "mysql init success");

    ret = a + b;
    return ret;
}

