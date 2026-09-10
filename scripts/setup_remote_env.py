"""生成 OAuth 管理员密码与远程服务 env 文件（600 权限），并校验摘要可用。"""
import os
import pathlib
import secrets

from linuxdo_mcp.oauth.security import hash_password, verify_password

CFG = pathlib.Path.home() / ".config/linuxdo-mcp"
CFG.mkdir(parents=True, exist_ok=True)

ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
password = "".join(secrets.choice(ALPHABET) for _ in range(24))
digest = hash_password(password)

pw_file = CFG / "oauth-admin-password.txt"
pw_file.write_text(password + "\n", encoding="utf-8")
pw_file.chmod(0o600)

env_file = CFG / "remote.env"
env_file.write_text(
    "MCP_TRANSPORT=streamable-http\n"
    "MCP_PUBLIC_URL=https://ldo.54xzh.com/mcp\n"
    f"MCP_OAUTH_PASSWORD_HASH='{digest}'\n"
    "MCP_OAUTH_ADMIN_USERNAME=admin\n"
    "MCP_HTTP_HOST=127.0.0.1\n"
    "MCP_HTTP_PORT=8011\n"
    "MCP_CONFIG_DIR=/home/ubuntu/.linuxdo-mcp\n",
    encoding="utf-8",
)
env_file.chmod(0o600)

# 回读校验：文件里存的摘要确实能验证这个密码
stored = [l for l in env_file.read_text().splitlines() if l.startswith("MCP_OAUTH_PASSWORD_HASH=")][0]
stored_hash = stored.split("=", 1)[1].strip().strip("'")
print("密码文件:", pw_file, oct(pw_file.stat().st_mode & 0o777))
print("env 文件:", env_file, oct(env_file.stat().st_mode & 0o777))
print("摘要回读校验:", verify_password(password, stored_hash))
print("摘要前缀:", stored_hash[:24], "...")
print("PASSWORD:", password)
