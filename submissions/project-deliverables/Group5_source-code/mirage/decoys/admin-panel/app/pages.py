"""Static content for the fake Halcyon Freight internal admin panel."""

LOGIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Halcyon Freight &middot; Operations Console</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #eef1f5; margin: 0; }}
  .card {{ max-width: 360px; margin: 12vh auto; background: #fff; padding: 32px; border-radius: 6px;
           box-shadow: 0 2px 10px rgba(0,0,0,.08); }}
  h1 {{ font-size: 18px; margin: 0 0 4px; color: #1d2b3a; }}
  p.sub {{ color: #6b7785; font-size: 13px; margin: 0 0 24px; }}
  label {{ display: block; font-size: 13px; color: #33414e; margin-bottom: 4px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 9px; margin-bottom: 16px; border: 1px solid #c9d1da;
           border-radius: 4px; }}
  button {{ width: 100%; padding: 10px; background: #1f5fa8; color: #fff; border: 0; border-radius: 4px; }}
  .err {{ background: #fdecea; color: #a12622; padding: 8px 10px; border-radius: 4px; font-size: 13px;
          margin-bottom: 16px; }}
  footer {{ text-align: center; color: #9aa5b1; font-size: 11px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="card">
  <h1>Operations Console</h1>
  <p class="sub">Halcyon Freight &mdash; internal use only</p>
  {error}
  <form method="post" action="/login">
    <label for="u">Username</label>
    <input id="u" name="username" autocomplete="username" required>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
  <footer>v3.8.2 &middot; IT Helpdesk ext. 4410</footer>
</div>
</body>
</html>
"""

LOGIN_ERROR = '<div class="err">Invalid username or password.</div>'

ROBOTS = """User-agent: *
Disallow: /backup/
Disallow: /api/internal/
"""

BACKUP_INDEX = """<html>
<head><title>Index of /backup/</title></head>
<body>
<h1>Index of /backup/</h1><hr><pre><a href="../">../</a>
<a href=".env.bak">.env.bak</a>                                           14-Sep-2026 02:13                 {size}
</pre><hr></body>
</html>
"""

ENV_BACKUP = """# Halcyon Freight ops console - production
# backup taken before the Sept migration, remove after cutover
APP_ENV=production
APP_DEBUG=false
APP_URL=https://ops.halcyon-freight.internal
APP_KEY=base64:Qm9Hk2v0c1N5dE1hcmtldEZyZWlnaHQyMDI2IQ==

DB_CONNECTION=pgsql
DB_HOST=10.66.0.31
DB_PORT=5432
DB_DATABASE=ops_console
DB_USERNAME=ops_app
DB_PASSWORD=pg_ops_7Yc!r2Lq

# deploy box, used by the release script
DEPLOY_HOST={host}
DEPLOY_USER={username}
DEPLOY_PASSWORD={password}

MAIL_HOST=smtp.halcyon-freight.internal
MAIL_PORT=587
MAIL_FROM_ADDRESS=noreply@halcyon-freight.com
"""

NOT_FOUND = """<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0 (Ubuntu)</center>
</body>
</html>
"""
