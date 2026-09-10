"""允许 `python -m linuxdo_mcp` 直接启动（避免 runpy 双导入告警）。"""

from .server import main

if __name__ == "__main__":
    main()
