"""把 OAuth 管理员密码改成用户指定的值（更新 remote.env 摘要 + 明文备忘文件）。"""
import pathlib
import sys

from linuxdo_mcp.oauth.security import hash_password, verify_password

NEW = sys.argv[1]
CFG = pathlib.Path.home() / ".config/linuxdo-mcp"
env_file = CFG / "remote.env"

digest = hash_password(NEW)
lines = env_file.read_text(encoding="utf-8").splitlines()
out = []
for line in lines:
    if line.startswith("MCP_OAUTH_PASSWORD_HASH="):
        out.append(f"MCP_OAUTH_PASSWORD_HASH='{digest}'")
    else:
        out.append(line)
env_file.write_text("\n".join(out) + "\n", encoding="utf-8")
env_file.chmod(0o600)

pw_file = CFG / "oauth-admin-password.txt"
pw_file.write_text(NEW + "\n", encoding="utf-8")
pw_file.chmod(0o600)

# 回读校验
stored = [l for l in env_file.read_text().splitlines() if l.startswith("MCP_OAUTH_PASSWORD_HASH=")][0]
stored_hash = stored.split("=", 1)[1].strip().strip("'")
lines_out = env_file.read_text().splitlines()
print("remote.env 行数:", len(lines_out))
for line in lines_out:
    if line.startswith("MCP_OAUTH_PASSWORD_HASH="):
        print("  摘要: " + line[:40] + " ...")
    else:
        print("  " + line)
print("新密码长度:", len(NEW))
print("新密码校验:", verify_password(NEW, stored_hash))
print("旧密码应失败:", verify_password("SVWBu5VRxfFpsoUKaSh9tvMb", stored_hash))
print("权限:", oct(env_file.stat().st_mode & 0o777), oct(pw_file.stat().st_mode & 0o777))
