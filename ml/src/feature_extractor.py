import re

SUSPICIOUS_KEYWORDS = [

"drop","truncate","delete",
"union","grant","revoke",
"copy","pg_sleep",
"pg_read_file",
"information_schema",
"pg_database",
"pg_roles",
"or 1=1",
"or '1'='1'",
"or 1 = 1",
"or '1' = '1'",
"--",
"/*",
"benchmark",
"exec",
"xp_",
"lock in share mode",
"for update"

]

def extract_features(query):

    q=query.lower()

    return {

        "length":len(q),

        "num_digits":
        len(re.findall(r'\d+',q)),

        "conditions":
        q.count("="),

        "where":
        int("where" in q),

        "joins":
        q.count("join"),

        "subqueries":
        max(
            q.count("select")-1,
            0
        ),

        "comments":
        int(
            "--" in q or
            "/*" in q
        ),

        "special_chars":
        len(
            re.findall(
                r'[%$#@;]',
                q
            )
        ),

        "keyword_hits":

        sum(

        1

        for k in
        SUSPICIOUS_KEYWORDS

        if k in q

        ),

        "union":

        int("union" in q),

        "drop":

        int("drop" in q),

        "delete":

        int("delete" in q),

        "multiple_queries":

        q.count(";"),

        "table_enum":

        int(
        "information_schema"
        in q
        ),

        "role_enum":

        int(
        "pg_roles"
        in q
        )

    }