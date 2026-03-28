idm-acn/
├── src/
│   ├── idm/
│   │   ├── __init__.py
│   │   ├── config.py          # 配置管理
│   │   ├── logger.py          # 日志配置
│   │   ├── models.py          # 数据模型
│   │   ├── crypto.py          # 加密签名工具
│   │   ├── agent_id.py        # Agent ID生成器
│   │   ├── vc_generator.py    # VC0证书生成器
│   │   ├── vc_validator.py    # VC验证器
│   │   ├── profile_manager.py # Profile存储管理
│   │   ├── idm_service.py     # IDM业务服务
│   │   └── main.py            # FastAPI入口
│   └── tests/
│       ├── __init__.py
│       └── test_idm.py
├── docs/
│   ├── README.md              # 项目说明
│   ├── QUICK_START.md         # 快速开始
│   ├── ARCHITECTURE.md        # 架构设计
│   └── API.md                 # API文档
├── profiles/                   # Agent Profile存储目录
├── logs/                       # 日志目录
├── certs/                      # 证书目录
├── requirements.txt            # 依赖包
├── start_idm.sh                # Linux启动脚本
└── start.bat                   # Windows启动脚本
