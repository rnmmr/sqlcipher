#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* This global variable is referenced by the patches in sqlite3.c:
   winRead() and seekAndRead() add this offset to every file read. */
int sqlcipher_ntqq_offset = 0;

/* Convert wide-char string to UTF-8 on Windows, passthrough on other platforms */
static char *wchar_to_utf8(const wchar_t *wstr)
{
#ifdef _WIN32
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char *utf8 = (char *)malloc(len);
    if (!utf8) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, utf8, len, NULL, NULL);
    return utf8;
#else
    size_t len = wcstombs(NULL, wstr, 0);
    if (len == (size_t)-1) return NULL;
    char *utf8 = (char *)malloc(len + 1);
    if (!utf8) return NULL;
    wcstombs(utf8, wstr, len + 1);
    return utf8;
#endif
}

static void print_usage(void)
{
    fprintf(stderr,
        "sqlcipher_ntqq - SQLCipher with NTQQ header offset support\n"
        "\n"
        "Usage: sqlcipher_ntqq.exe [--header-offset N] [--key PASSWORD] <database.db>\n"
        "\n"
        "  --header-offset N   Skip N bytes at the beginning of the database file\n"
        "                      before reading SQLCipher pages (default: 0)\n"
        "  --key PASSWORD      SQLCipher encryption key (default: none = plaintext)\n"
        "\n"
        "SQL statements are read from stdin. Results are printed to stdout.\n"
        "Use .exit or .quit to quit, .help for this message.\n");
}

static int exec_callback(void *pArg, int nCols, char **colVals, char **colNames)
{
    for (int i = 0; i < nCols; i++)
    {
        if (i > 0) printf("|");
        printf("%s", colVals[i] ? colVals[i] : "NULL");
    }
    printf("\n");
    return 0;
}

static int header_callback(void *pArg, int nCols, char **colVals, char **colNames)
{
    int *first = (int *)pArg;
    if (!*first)
    {
        /* Print header */
        for (int i = 0; i < nCols; i++)
        {
            if (i > 0) printf("|");
            printf("%s", colNames[i]);
        }
        printf("\n");
        /* Print separator */
        for (int i = 0; i < nCols; i++)
        {
            if (i > 0) printf("|");
            int n = (int)strlen(colNames[i]);
            for (int j = 0; j < n; j++) printf("-");
        }
        printf("\n");
        *first = 1;
    }
    return exec_callback(pArg, nCols, colVals, colNames);
}

int wmain(int argc, wchar_t *argv[])
{
    char *dbFile = NULL;
    char *dbKey = NULL;
    int headerOffset = 0;
    int i;

    /* Parse arguments */
    for (i = 1; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--header-offset") == 0)
        {
            if (i + 1 < argc)
            {
                headerOffset = (int)wcstol(argv[++i], NULL, 10);
                if (headerOffset < 0)
                {
                    fprintf(stderr, "Error: header-offset must be non-negative.\n");
                    return 1;
                }
            }
            else
            {
                fprintf(stderr, "Error: --header-offset requires a value.\n");
                return 1;
            }
        }
        else if (wcscmp(argv[i], L"--key") == 0)
        {
            if (i + 1 < argc)
            {
                dbKey = wchar_to_utf8(argv[++i]);
                if (!dbKey) { fprintf(stderr, "Error: Memory allocation failed.\n"); return 1; }
            }
            else
            {
                fprintf(stderr, "Error: --key requires a value.\n");
                return 1;
            }
        }
        else if (wcscmp(argv[i], L"--help") == 0)
        {
            print_usage();
            return 0;
        }
        else if (argv[i][0] != L'-')
        {
            dbFile = wchar_to_utf8(argv[i]);
            if (!dbFile) { fprintf(stderr, "Error: Memory allocation failed.\n"); return 1; }
        }
        else
        {
            fprintf(stderr, "Error: Unknown option: %ls\n", argv[i]);
            return 1;
        }
    }

    /* Set the global header offset (used by patched winRead/seekAndRead) */
    sqlcipher_ntqq_offset = headerOffset;

    if (!dbFile)
    {
        print_usage();
        return 1;
    }

    fprintf(stderr, "Header offset: %d bytes\n", headerOffset);
    fprintf(stderr, "Opening database: %s\n", dbFile);

    sqlite3 *db = NULL;
    int rc = sqlite3_open(dbFile, &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Error: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(dbFile);
        free(dbKey);
        return 1;
    }

    /* Apply SQLCipher key if provided */
    if (dbKey)
    {
        char pragma[4096];
        snprintf(pragma, sizeof(pragma), "PRAGMA key = '%s';", dbKey);
        char *errMsg = NULL;
        rc = sqlite3_exec(db, pragma, NULL, NULL, &errMsg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Error setting key: %s\n", errMsg);
            sqlite3_free(errMsg);
        }
    }

    fprintf(stderr, "Reading SQL from stdin...\n");
    fprintf(stderr, "sqlite> ");

    char line[65536];
    char *sql = (char *)malloc(1);
    if (!sql) { fprintf(stderr, "Error: Out of memory.\n"); return 1; }
    sql[0] = '\0';
    int sqlLen = 0;

    while (fgets(line, sizeof(line), stdin))
    {
        /* Remove trailing newline */
        size_t lineLen = strlen(line);
        while (lineLen > 0 && (line[lineLen - 1] == '\n' || line[lineLen - 1] == '\r'))
            line[--lineLen] = '\0';

        /* Handle dot-commands */
        if (line[0] == '.' && sqlLen == 0)
        {
            if (strcmp(line, ".exit") == 0 || strcmp(line, ".quit") == 0)
                break;
            else if (strcmp(line, ".help") == 0)
            {
                print_usage();
                fprintf(stderr, "sqlite> ");
                fflush(stderr);
                continue;
            }
            else
            {
                fprintf(stderr, "Error: Unknown dot-command: %s\n", line);
                fprintf(stderr, "sqlite> ");
                fflush(stderr);
                continue;
            }
        }

        /* Accumulate SQL */
        int newLen = sqlLen + (int)lineLen + 2;
        char *tmp = (char *)realloc(sql, newLen);
        if (!tmp)
        {
            fprintf(stderr, "Error: Out of memory.\n");
            break;
        }
        sql = tmp;
        if (sqlLen > 0)
        {
            strcat(sql, "\n");
            sqlLen++;
        }
        strcat(sql, line);
        sqlLen += (int)lineLen;

        /* Trim trailing whitespace to check for semicolon */
        char *end = sql + sqlLen - 1;
        while (end >= sql && (*end == ' ' || *end == '\t' || *end == '\n'))
            end--;
        if (end < sql || *end != ';')
        {
            fprintf(stderr, "   ...> ");
            fflush(stderr);
            continue;
        }

        /* Execute the SQL */
        char *errMsg = NULL;
        int firstRow = 0;

        rc = sqlite3_exec(db, sql, header_callback, &firstRow, &errMsg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Error: %s\n", errMsg);
            sqlite3_free(errMsg);
        }
        else if (!firstRow)
        {
            /* Query with no rows returned, or DML statement */
            /* For DML, sqlite3_exec returns SQLITE_DONE but callback never called */
        }

        /* Reset SQL buffer */
        free(sql);
        sql = (char *)malloc(1);
        if (!sql) { fprintf(stderr, "Error: Out of memory.\n"); break; }
        sql[0] = '\0';
        sqlLen = 0;

        fprintf(stderr, "sqlite> ");
        fflush(stderr);
    }

    free(sql);
    sqlite3_close(db);
    free(dbFile);
    free(dbKey);

    fprintf(stderr, "\nDone.\n");
    return 0;
}
