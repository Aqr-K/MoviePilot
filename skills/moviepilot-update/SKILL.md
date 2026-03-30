---
name: moviepilot-update
description: Use this skill when you need to restart or upgrade MoviePilot. This skill covers system restart, version check, and manual upgrade procedures.
---

# MoviePilot System Update & Restart

> All script paths are relative to this skill file.

This skill provides capabilities to restart MoviePilot service, check for updates, and perform manual upgrades.

## Restart MoviePilot

### Method 1: Using REST API (Recommended)

Call the restart endpoint with admin authentication:

```bash
# Using moviepilot-api skill
python scripts/mp-api.py GET /api/v1/system/restart
```

Or with curl:
```bash
curl -X GET "http://localhost:3000/api/v1/system/restart" \
  -H "X-API-KEY: <YOUR_API_TOKEN>"
```

**Note:** This API will restart the Docker container internally. The service will be briefly unavailable during restart.

### Method 2: Using execute_command tool

If you have admin privileges, you can execute the restart command directly:

```bash
docker restart moviepilot
```

## Check for Updates

### Method 1: Using REST API

```bash
python scripts/mp-api.py GET /api/v1/system/versions
```

This returns all available GitHub releases.

### Method 2: Check current version

```bash
# Check current version
cat /app/version.py
```

## Upgrade MoviePilot

### Option 1: Automatic Update (Recommended)

Set the environment variable `MOVIEPILOT_AUTO_UPDATE` and restart:

1. **For Docker Compose users:**
   ```bash
   # Edit docker-compose.yml, add environment variable:
   environment:
     - MOVIEPILOT_AUTO_UPDATE=release  # or "dev" for dev版本
   
   # Then restart
   docker-compose down && docker-compose up -d
   ```

2. **For Docker run users:**
   ```bash
   docker stop moviepilot
   docker rm moviepilot
   docker run -d ... -e MOVIEPILOT_AUTO_UPDATE=release jxxghp/moviepilot
   ```

The update script (`/usr/local/bin/mp_update.sh` or `/app/docker/update.sh`) will automatically:
- Check GitHub for latest release
- Download new backend code
- Update dependencies if changed
- Download new frontend
- Update site resources
- Restart the service

### Option 2: Manual Upgrade

If you need to manually download and apply updates:

1. **Get latest release version:**
   ```bash
   curl -s https://api.github.com/repos/jxxghp/MoviePilot/releases | grep '"tag_name"' | grep "v2" | head -1
   ```

2. **Download and extract backend:**
   ```bash
   # Replace v2.x.x with actual version
   curl -L -o /tmp/backend.zip https://github.com/jxxghp/MoviePilot/archive/refs/tags/v2.x.x.zip
   unzip -d /tmp/backend /tmp/backend.zip
   ```

3. **Backup and replace:**
   ```bash
   # Backup current installation
   cp -r /app /app_backup
   
   # Replace files (exclude config and plugins)
   cp -r /tmp/backend/MoviePilot-*/* /app/
   ```

4. **Restart MoviePilot:**
   ```bash
   # Use API or docker restart
   python scripts/mp-api.py GET /api/v1/system/restart
   ```

### Important Notes

- **Backup first:** Before upgrading, backup your configuration and database
- **Dependencies:** Check if requirements.in has changes; if so, update virtual environment
- **Plugins:** The update script automatically backs up and restores plugins
- **Non-Docker:** For non-Docker installations, use `git pull` or `pip install -U moviepilot`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Restart fails | Check if Docker daemon is running; verify container has restart policy |
| Update fails | Check network connectivity to GitHub; ensure sufficient disk space |
| Version unchanged | Verify `MOVIEPILOT_AUTO_UPDATE` environment variable is set correctly |
| Dependency errors | May need to rebuild virtual environment: `pip-compile requirements.in && pip install -r requirements.txt` |

## Environment Variables for Auto-Update

| Variable | Value | Description |
|----------|-------|-------------|
| `MOVIEPILOT_AUTO_UPDATE` | `release` | Auto-update to latest stable release |
| `MOVIEPILOT_AUTO_UPDATE` | `dev` | Auto-update to latest dev version |
| `MOVIEPILOT_AUTO_UPDATE` | `false` | Disable auto-update (default) |
| `GITHUB_TOKEN` | (token) | GitHub token for higher rate limits |
| `GITHUB_PROXY` | (url) | GitHub proxy URL for China users |
| `PROXY_HOST` | (url) | Global proxy host |
