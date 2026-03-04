# ELWARDANI Deployment Guide — elwardani.me

## Files Fixed
| File | What was fixed |
|------|---------------|
| `app.py` | Resolved all Git merge conflicts, cleaned merged code |
| `.env` | Added elwardani.me to ALLOWED_ORIGINS, set HOST=0.0.0.0, ENFORCE_HTTPS=true |
| `index.html` | Removed hardcoded `http://127.0.0.1:5000` from CSP connect-src |

---

## Server Setup (Ubuntu VPS)

### 1. Upload files to your server
```bash
scp app.py .env index.html styles.css app.js dataset.csv generate_dataset.py requirements.txt user@elwardani.me:/var/www/elwardani/
```

### 2. Install Python dependencies
```bash
cd /var/www/elwardani
pip install -r requirements.txt
python generate_dataset.py   # creates dataset.csv if not present
```

### 3. Run with Gunicorn (production)
```bash
pip install gunicorn
gunicorn -w 2 -b 127.0.0.1:5000 app:app --daemon --log-file logs/gunicorn.log
```

### 4. Nginx reverse proxy config
Create `/etc/nginx/sites-available/elwardani`:
```nginx
server {
    listen 80;
    server_name elwardani.me www.elwardani.me;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name elwardani.me www.elwardani.me;

    ssl_certificate     /etc/letsencrypt/live/elwardani.me/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/elwardani.me/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```
```bash
ln -s /etc/nginx/sites-available/elwardani /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### 5. Free SSL with Certbot
```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d elwardani.me -d www.elwardani.me
```

### 6. Systemd service (auto-start)
Create `/etc/systemd/system/elwardani.service`:
```ini
[Unit]
Description=ELWARDANI Anomaly Detection
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/elwardani
ExecStart=/usr/bin/gunicorn -w 2 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
systemctl enable elwardani
systemctl start elwardani
```

---

## Change the SECRET_KEY!
Edit `.env` and set a random SECRET_KEY before deploying:
```
SECRET_KEY=your-very-long-random-string-here
```
