# PII-AIRLOCK 开发路线图

> 文档版本：v1.0
> 创建日期：2026-01-21
> 状态：MVP 已完成

## MVP 开发计划

### Phase 1: 核心引擎 ✅

**目标**：实现 PII 识别与脱敏的核心闭环

**任务清单**：
- [x] 集成 Microsoft Presidio
- [x] 实现 `Text → Anonymized Text → Deanonymized Text` 闭环
- [x] 支持基础 PII 类型：姓名、邮箱、电话
- [x] 编写核心引擎单元测试

**交付物**：
- `src/core/anonymizer.py` - 脱敏引擎
- `src/core/deanonymizer.py` - 回填引擎
- `tests/test_core.py` - 核心功能测试

---

### Phase 2: 代理服务 ✅

**目标**：搭建 OpenAI API 兼容的代理层

**任务清单**：
- [x] 搭建 FastAPI 服务器
- [x] 实现 `/v1/chat/completions` 接口透传
- [x] 接入 Redis 存储映射关系
- [x] 实现请求/响应的脱敏和回填流程

**交付物**：
- `src/api/routes.py` - API 路由
- `src/api/proxy.py` - 代理逻辑
- `src/storage/redis.py` - Redis 存储层
- `docker-compose.yml` - 开发环境配置

---

### Phase 3: 流式处理与优化 ✅

**目标**：支持 SSE 流式响应

**任务清单**：
- [x] 实现滑动窗口缓冲机制
- [x] 攻克 SSE 流式替换问题
- [x] 编写 Dockerfile
- [x] 完善 docker-compose.yml，确保一行命令启动

**交付物**：
- `src/streaming/buffer.py` - 滑动窗口实现
- `Dockerfile` - 生产镜像
- 完整的 Docker 部署方案

---

### Phase 4: 规则配置与 UI ✅

**目标**：提供配置化能力和测试界面

**任务清单**：
- [x] 实现自定义正则配置 (`regex.yaml`)
- [x] 提供简单的 Web UI 测试脱敏效果
- [x] 编写用户文档

**交付物**：
- `config/regex.yaml` - 自定义规则配置
- `src/ui/` - Web UI 组件
- `docs/user-guide.md` - 用户指南

---

### Phase 5: 生产优化 ✅

**目标**：生产级监控、限流和性能优化

**任务清单**：
- [x] 实现结构化日志 (JSON 格式)
- [x] 实现 Prometheus 指标收集
- [x] 实现 API 限流 (令牌桶算法)
- [x] 优化 HTTP 连接池
- [x] 优化 Presidio Analyzer 单例模式
- [x] 实现 MemoryStore 后台清理线程

**交付物**：
- `src/logging/setup.py` - 日志配置
- `src/metrics/collectors.py` - Prometheus 指标
- `src/api/middleware.py` - 请求日志中间件
- `src/api/limiter.py` - API 限流配置

---

## 后续迭代方向

### Phase 6: 企业级增强 (v1.2.0) ✅ 已完成

**目标**：实现 GDPR/CCPA/PIPL 合规与企业级安全功能

**任务清单**：
- [x] 仿真数据合成 (Synthetic Replacement) - 姓名/手机/邮箱/身份证生成器
- [x] 模糊匹配纠错 (Fuzzy Rehydration) - 幻觉自愈机制
- [x] 审计日志系统 (Audit Logging) - 完整的审计 API
- [x] 秘密泄露防护库 (Secret Scanning) - 30+ 预定义模式
- [x] 合规预设配置 (Compliance Presets) - GDPR/CCPA/PIPL/Financial
- [x] 公众人物白名单 (Allowlist) - 避免误脱敏知名人物
- [x] 高熵值检测 (Entropy Detector) - 发现未知格式的密钥
- [x] 可视化调试界面 (Debug UI) - 双屏对照调试
- [x] OpenAI API 扩展 - Function Calling/Vision/Embeddings 支持

**交付物**：
- `config/compliance_presets/` - 合规预设配置 (GDPR, CCPA, PIPL, Financial)
- `config/allowlists/` - 白名单目录 (公众人物、常见地名)
- `src/core/synthetic/` - 仿真数据生成器
- `src/core/fuzzy/` - 模糊匹配引擎
- `src/audit/` - 审计日志模块
- `src/recognizers/secret_scanner/` - 秘密扫描器
- `src/recognizers/allowlist.py` - 白名单识别器
- `src/recognizers/entropy_detector.py` - 高熵值检测器
- `src/api/compliance_api.py` - 合规 API
- `src/static/debug.html` - 可视化调试界面

---

### Phase 7.1: Web 管理界面 (v1.2.1) ✅ 已完成

**目标**：提供图形化配置界面，降低使用门槛

**任务清单**：
- [x] 合规配置页面 - 下拉选择预设，可视化显示当前配置差异，一键激活/切换
- [x] 白名单管理页面 - 添加/删除白名单条目，批量导入，搜索和过滤功能
- [x] 审计日志查询页面 - 时间范围选择，事件类型过滤，导出功能
- [x] 系统仪表盘 - 实时统计，最近活动

**交付物**：
- `src/static/admin.html` - 管理界面 (单页应用)
- `src/api/allowlist_api.py` - 白名单管理 API
- `/admin` 路由 - 管理界面入口

**功能亮点**：
- 响应式设计，支持移动端
- 暗色主题，符合开发者习惯
- 实时数据更新
- 无需刷新的流畅交互

---

### Phase 7.2: 语义感知白名单 (v1.3.0) 📋 计划中

**目标**：区分"询问"与"陈述"场景，智能豁免

**任务清单**：
- [ ] 意图检测 - 识别询问模式 ("Who is...", "...是谁")
- [ ] 上下文分析 - 在询问上下文中跳过白名单项脱敏
- [ ] 语义判断实现

---

### Phase 8: 扩展功能 (v1.4.0) 📋 计划中

**目标**：多语言支持与性能优化

**任务清单**：
- [ ] 支持英文 PII 识别
- [ ] 支持日文 PII 识别
- [ ] 集成 HuggingFace Transformers 提升识别准确率
- [ ] Redis Cluster 支持
- [ ] 分布式限流

---

### Phase 9: 可观测性 (v1.5.0) 📋 计划中

**目标**：完整的企业级可观测性

**任务清单**：
- [ ] OpenTelemetry 集成
- [ ] 分布式追踪
- [ ] 性能分析面板
- [ ] 异常检测与告警

---

### v2.0 - 高性能版本 🔮 远期规划

**目标**：支持更高并发的大规模部署

**任务清单**：
- [ ] Go 语言重写核心代理层
- [ ] 支持水平扩展
- [ ] 分布式 Redis 集群
- [ ] gRPC 协议支持
