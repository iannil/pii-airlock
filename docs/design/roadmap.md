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

### v1.1 - 增强识别能力
- 支持更多语言（英文、日文等）
- 集成 HuggingFace Transformers 提升识别准确率
- 添加置信度阈值配置

### v1.2 - 企业特性
- 多租户支持
- 审计日志
- 访问控制

### v2.0 - 高性能版本
- Go 语言重写核心代理层
- 支持更高并发
- 分布式 Redis 集群
