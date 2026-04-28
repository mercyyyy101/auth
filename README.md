# Custom Auth Panel

License key management system with web-based admin panel.

## Default Credentials
- **Username:** `imudfrsuckit`
- **Password:** `udforeverfn`

To change, set `ADMIN_PASSWORD` environment variable or edit `server.js` line 10.

## Deployment Options

### Option 1: Render (Recommended - Free)

1. Push this `auth-panel` folder to a GitHub repo
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your GitHub repo
4. Deploy (no env vars needed for default credentials)

### Option 2: Vercel

1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` in this folder
3. Deploy

### Option 3: Self-Host (Local)

```bash
cd auth-panel
npm install
npm start
# Open http://localhost:3000
```

## Configuring the Client

After deploying, edit `base/src/auth/auth.cpp` and change:

```cpp
#define API_HOST L"your-auth-api.onrender.com"
```

Replace with your actual URL.

## Features

- **License Key Management**: Generate, enable/disable, delete keys
- **HWID Binding**: Each key binds to first HWID used
- **Expiration Dates**: Set optional expiration when creating keys
- **Access Logs**: Track all validation attempts
- **Dashboard Stats**: Total/active/expired key counts

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/validate` | POST | Client validation (key + hwid) |
| `/api/admin/login` | POST | Admin login |
| `/api/admin/licenses` | GET | List all keys |
| `/api/admin/licenses` | POST | Create new key |
| `/api/admin/licenses/:key` | DELETE | Delete key |
| `/api/admin/licenses/:key` | PATCH | Toggle key status |
| `/api/admin/logs` | GET | View access logs |
| `/api/admin/stats` | GET | Get statistics |
