# PII-AIRLOCK 文档中心

## 文档结构

```
docs/
├── design/              # 设计文档
│   ├── architecture.md  # 技术架构设计
│   └── roadmap.md       # 开发路线图
├── progress/            # 进展追踪
│   ├── changelog.md     # 变更日志
│   └── status-report.md # 项目状态报告
└── archive/             # 归档文档
```

## 快速导航

### 设计文档
- [技术架构设计](design/architecture.md) - 系统架构、核心流程、技术栈
- [开发路线图](design/roadmap.md) - MVP 计划、迭代规划

### 进展追踪
- [变更日志](progress/changelog.md) - 项目进展时间线
- [状态报告](progress/status-report.md) - 完整项目状态、文件清单、技术债务

### 归档文档
*暂无归档文档*

## 文档规范

| 目录 | 用途 | 何时使用 |
|------|------|----------|
| `design/` | 设计方案 | 新功能设计、架构变更 |
| `progress/` | 进展记录 | 迭代完成、状态更新 |
| `archive/` | 历史归档 | 废弃设计、旧版文档 |

## 维护说明

1. **新增设计文档**：放入 `design/` 目录
2. **记录进展**：更新 `progress/changelog.md`
3. **废弃文档**：移至 `archive/`，添加日期前缀
4. **定期审查**：每个迭代结束时更新 `status-report.md`
