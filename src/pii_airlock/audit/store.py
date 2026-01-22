"""
审计日志存储

定义审计日志的存储抽象和具体实现。
支持文件存储（开发环境）、Redis存储（生产环境）、
数据库存储（生产环境）和内存存储（测试）。
"""

import asyncio
import json
import csv
import os
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import aiofiles
import aiofiles.os

from pii_airlock.audit.models import (
    AuditEvent,
    AuditFilter,
    AuditSummary,
    AuditEventType,
    RiskLevel,
)


class AuditStore(ABC):
    """审计日志存储抽象接口"""

    @abstractmethod
    async def write(self, event: AuditEvent) -> None:
        """写入审计事件

        Args:
            event: 要写入的审计事件
        """
        pass

    @abstractmethod
    async def write_batch(self, events: list[AuditEvent]) -> None:
        """批量写入审计事件

        Args:
            events: 要写入的审计事件列表
        """
        pass

    @abstractmethod
    async def query(self, filter: AuditFilter) -> list[AuditEvent]:
        """查询审计事件

        Args:
            filter: 查询过滤器

        Returns:
            匹配的审计事件列表
        """
        pass

    @abstractmethod
    async def export_json(
        self, filter: AuditFilter, *, pretty: bool = False
    ) -> str:
        """导出为 JSON 格式

        Args:
            filter: 查询过滤器
            pretty: 是否格式化输出

        Returns:
            JSON 字符串
        """
        pass

    @abstractmethod
    async def export_csv(self, filter: AuditFilter) -> str:
        """导出为 CSV 格式

        Args:
            filter: 查询过滤器

        Returns:
            CSV 字符串
        """
        pass

    @abstractmethod
    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: Optional[str] = None,
    ) -> AuditSummary:
        """获取审计统计摘要

        Args:
            start_date: 统计开始日期
            end_date: 统计结束日期
            tenant_id: 租户 ID（可选）

        Returns:
            审计统计摘要
        """
        pass

    @abstractmethod
    async def cleanup_old_logs(self, retention_days: int) -> int:
        """清理旧日志

        Args:
            retention_days: 保留天数

        Returns:
            删除的日志条目数
        """
        pass


class FileAuditStore(AuditStore):
    """文件审计日志存储

    适用于开发环境和小规模部署。
    按日期自动轮转日志文件。
    """

    def __init__(
        self,
        log_dir: str | Path = "./logs/audit",
        rotation: str = "daily",  # daily, weekly, monthly
        compress: bool = True,
    ):
        """初始化文件审计存储

        Args:
            log_dir: 日志目录
            rotation: 轮转策略
            compress: 是否压缩旧日志
        """
        self.log_dir = Path(log_dir)
        self.rotation = rotation
        self.compress = compress
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # 创建锁文件防止并发写入冲突
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, file_path: str) -> asyncio.Lock:
        """获取文件锁"""
        if file_path not in self._locks:
            self._locks[file_path] = asyncio.Lock()
        return self._locks[file_path]

    def _get_log_file(self, date: datetime) -> Path:
        """获取指定日期的日志文件路径"""
        if self.rotation == "daily":
            filename = date.strftime("audit_%Y%m%d.jsonl")
        elif self.rotation == "weekly":
            # 使用 ISO 周数
            week_number = date.isocalendar()[1]
            filename = date.strftime(f"audit_%Y{week_number:02d}.jsonl")
        else:  # monthly
            filename = date.strftime("audit_%Y%m.jsonl")

        return self.log_dir / filename

    def _get_log_files_in_range(
        self, start_date: datetime, end_date: datetime
    ) -> list[Path]:
        """获取日期范围内的所有日志文件"""
        files = []
        current = start_date.date()
        end = end_date.date()

        while current <= end:
            log_file = self._get_log_file(datetime.combine(current, datetime.min.time()))
            if log_file.exists():
                files.append(log_file)
            current += timedelta(days=1)

        # 按日期排序
        files.sort()
        return files

    async def write(self, event: AuditEvent) -> None:
        """写入审计事件"""
        log_file = self._get_log_file(event.timestamp)
        lock = self._get_lock(str(log_file))

        async with lock:
            async with aiofiles.open(log_file, mode="a", encoding="utf-8") as f:
                await f.write(event.to_json() + "\n")

    async def write_batch(self, events: list[AuditEvent]) -> None:
        """批量写入审计事件"""
        if not events:
            return

        # 按日期分组
        grouped: dict[Path, list[AuditEvent]] = {}
        for event in events:
            log_file = self._get_log_file(event.timestamp)
            if log_file not in grouped:
                grouped[log_file] = []
            grouped[log_file].append(event)

        # 并发写入每个文件
        tasks = []
        for log_file, file_events in grouped.items():
            lock = self._get_lock(str(log_file))
            tasks.append(self._write_to_file(log_file, file_events, lock))

        await asyncio.gather(*tasks)

    async def _write_to_file(
        self, log_file: Path, events: list[AuditEvent], lock: asyncio.Lock
    ) -> None:
        """写入单个文件"""
        async with lock:
            async with aiofiles.open(log_file, mode="a", encoding="utf-8") as f:
                for event in events:
                    await f.write(event.to_json() + "\n")

    async def query(self, filter: AuditFilter) -> list[AuditEvent]:
        """查询审计事件"""
        events = []

        # 找出需要查询的日志文件
        log_files = self._get_log_files_in_range(filter.start_date, filter.end_date)

        # 读取并过滤
        for log_file in log_files:
            async with aiofiles.open(log_file, mode="r", encoding="utf-8") as f:
                async for line in f:
                    try:
                        event = AuditEvent.from_json(line.strip())
                        if filter.match(event):
                            events.append(event)
                    except (json.JSONDecodeError, ValueError):
                        # 跳过无效行
                        continue

        # 排序
        reverse = filter.sort_order == "desc"
        events.sort(key=lambda e: getattr(e, filter.sort_by), reverse=reverse)

        # 分页
        offset = filter.offset
        limit = filter.limit
        return events[offset:offset + limit]

    async def export_json(
        self, filter: AuditFilter, *, pretty: bool = False
    ) -> str:
        """导出为 JSON 格式"""
        events = await self.query(filter)

        if pretty:
            return json.dumps([e.to_dict() for e in events], ensure_ascii=False, indent=2)
        return json.dumps([e.to_dict() for e in events], ensure_ascii=False)

    async def export_csv(self, filter: AuditFilter) -> str:
        """导出为 CSV 格式"""
        events = await self.query(filter)

        import io
        output = io.StringIO()
        fieldnames = [
            "event_id", "event_type", "timestamp", "tenant_id", "user_id",
            "request_id", "entity_type", "entity_count", "strategy_used",
            "source_ip", "endpoint", "method", "status_code", "risk_level",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            writer.writerow({
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "tenant_id": event.tenant_id or "",
                "user_id": event.user_id or "",
                "request_id": event.request_id or "",
                "entity_type": event.entity_type or "",
                "entity_count": event.entity_count,
                "strategy_used": event.strategy_used or "",
                "source_ip": event.source_ip or "",
                "endpoint": event.endpoint or "",
                "method": event.method or "",
                "status_code": event.status_code or "",
                "risk_level": event.risk_level.value,
            })

        return output.getvalue()

    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: Optional[str] = None,
    ) -> AuditSummary:
        """获取审计统计摘要"""
        filter = AuditFilter(
            start_date=start_date,
            end_date=end_date,
            tenant_id=tenant_id,
            limit=100000,  # 大限制以获取所有数据
        )

        events = await self.query(filter)

        summary = AuditSummary(
            period_start=start_date,
            period_end=end_date,
            tenant_id=tenant_id,
            total_events=len(events),
        )

        for event in events:
            # 按类型统计
            event_type = event.event_type.value
            summary.events_by_type[event_type] = (
                summary.events_by_type.get(event_type, 0) + 1
            )

            # 按风险级别统计
            risk = event.risk_level.value
            summary.events_by_risk[risk] = (
                summary.events_by_risk.get(risk, 0) + 1
            )

            # PII 统计
            if event.event_type == AuditEventType.PII_DETECTED:
                summary.pii_detected_count += event.entity_count
                if event.entity_type:
                    summary.pii_by_type[event.entity_type] = (
                        summary.pii_by_type.get(event.entity_type, 0) + event.entity_count
                    )
            elif event.event_type == AuditEventType.PII_ANONYMIZED:
                summary.pii_anonymized_count += event.entity_count
                if event.strategy_used:
                    summary.pii_by_strategy[event.strategy_used] = (
                        summary.pii_by_strategy.get(event.strategy_used, 0) + 1
                    )

            # API 统计
            if event.event_type == AuditEventType.API_REQUEST:
                summary.api_request_count += 1
            elif event.event_type == AuditEventType.API_ERROR:
                summary.api_error_count += 1

            # 安全统计
            if event.event_type == AuditEventType.AUTH_FAILURE:
                summary.auth_failure_count += 1
            elif event.event_type == AuditEventType.RATE_LIMIT_EXCEEDED:
                summary.rate_limit_count += 1
            elif event.event_type == AuditEventType.SECRET_DETECTED:
                summary.secret_detected_count += 1

        return summary

    async def cleanup_old_logs(self, retention_days: int) -> int:
        """清理旧日志"""
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_count = 0

        for log_file in self.log_dir.glob("audit_*.jsonl"):
            # 从文件名提取日期
            try:
                stem = log_file.stem  # 去掉 .jsonl
                if self.rotation == "daily":
                    file_date = datetime.strptime(stem.replace("audit_", ""), "%Y%m%d")
                elif self.rotation == "monthly":
                    file_date = datetime.strptime(stem.replace("audit_", ""), "%Y%m")
                else:
                    # weekly
                    year = int(stem[6:10])
                    week = int(stem[10:12])
                    file_date = datetime.strptime(f"{year}-{week}-1", "%Y-%W-%w")

                if file_date < cutoff_date:
                    await aiofiles.os.remove(log_file)
                    deleted_count += 1

                    # 如果需要压缩，可以在这里添加压缩逻辑
                    # 压缩后的文件名如: audit_20240101.jsonl.gz

            except (ValueError, IndexError):
                # 无法解析日期的文件，跳过
                continue

        return deleted_count


class DatabaseAuditStore(AuditStore):
    """数据库审计日志存储

    适用于生产环境。支持 PostgreSQL、MySQL、SQLite。
    使用连接池和批量写入优化性能。
    """

    def __init__(
        self,
        db_url: str,
        pool_size: int = 10,
        batch_size: int = 100,
        batch_interval_ms: int = 1000,
    ):
        """初始化数据库审计存储

        Args:
            db_url: 数据库连接 URL (支持 sqlite://, postgresql://, mysql://)
            pool_size: 连接池大小
            batch_size: 批量写入大小
            batch_interval_ms: 批量刷新间隔
        """
        self.db_url = db_url
        self.pool_size = pool_size
        self.batch_size = batch_size
        self.batch_interval_ms = batch_interval_ms

        self._pool = None
        self._pending_events: list[AuditEvent] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def _init(self):
        """初始化数据库连接和表结构"""
        if self._initialized:
            return

        import asyncpg  # PostgreSQL
        import aiosqlite  # SQLite

        if self.db_url.startswith("sqlite://"):
            self._db_type = "sqlite"
            self._pool = await aiosqlite.connect(
                self.db_url.replace("sqlite://", "")
            )
            await self._create_tables_sqlite()
        elif self.db_url.startswith("postgresql://"):
            self._db_type = "postgresql"
            self._pool = await asyncpg.create_pool(
                self.db_url, min_size=1, max_size=self.pool_size
            )
            await self._create_tables_postgresql()
        else:
            raise NotImplementedError(f"Unsupported database: {self.db_url}")

        self._initialized = True

    async def _create_tables_sqlite(self):
        """创建 SQLite 表结构"""
        await self._pool.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tenant_id TEXT,
                user_id TEXT,
                request_id TEXT,
                entity_type TEXT,
                entity_count INTEGER DEFAULT 0,
                strategy_used TEXT,
                source_ip TEXT,
                user_agent TEXT,
                api_key_hash TEXT,
                endpoint TEXT,
                method TEXT,
                status_code INTEGER,
                error_message TEXT,
                risk_level TEXT DEFAULT 'none',
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 创建索引
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_logs(timestamp)
        """)
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp
            ON audit_logs(tenant_id, timestamp)
        """)
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_event_type
            ON audit_logs(event_type)
        """)
        await self._pool.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_request_id
            ON audit_logs(request_id)
        """)

    async def _create_tables_postgresql(self):
        """创建 PostgreSQL 表结构"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id BIGSERIAL PRIMARY KEY,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    tenant_id TEXT,
                    user_id TEXT,
                    request_id TEXT,
                    entity_type TEXT,
                    entity_count INTEGER DEFAULT 0,
                    strategy_used TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    api_key_hash TEXT,
                    endpoint TEXT,
                    method TEXT,
                    status_code INTEGER,
                    error_message TEXT,
                    risk_level TEXT DEFAULT 'none',
                    metadata JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # 创建索引
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_logs(timestamp DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp
                ON audit_logs(tenant_id, timestamp DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_logs(event_type)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_request_id
                ON audit_logs(request_id)
            """)

    async def write(self, event: AuditEvent) -> None:
        """写入审计事件"""
        await self._init()

        if self.db_type == "sqlite":
            await self._write_sqlite(event)
        else:
            await self._write_postgresql(event)

    @property
    def db_type(self) -> str:
        """获取数据库类型"""
        return getattr(self, "_db_type", None)

    async def _write_sqlite(self, event: AuditEvent) -> None:
        """SQLite 写入"""
        await self._pool.execute("""
            INSERT INTO audit_logs (
                event_id, event_type, timestamp, tenant_id, user_id, request_id,
                entity_type, entity_count, strategy_used, source_ip, user_agent,
                api_key_hash, endpoint, method, status_code, error_message,
                risk_level, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            event.event_id,
            event.event_type.value,
            event.timestamp.isoformat(),
            event.tenant_id,
            event.user_id,
            event.request_id,
            event.entity_type,
            event.entity_count,
            event.strategy_used,
            event.source_ip,
            event.user_agent,
            event.api_key_hash,
            event.endpoint,
            event.method,
            event.status_code,
            event.error_message,
            event.risk_level.value,
            json.dumps(event.metadata) if event.metadata else None,
        )

    async def _write_postgresql(self, event: AuditEvent) -> None:
        """PostgreSQL 写入"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO audit_logs (
                    event_id, event_type, timestamp, tenant_id, user_id, request_id,
                    entity_type, entity_count, strategy_used, source_ip, user_agent,
                    api_key_hash, endpoint, method, status_code, error_message,
                    risk_level, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            """,
                event.event_id,
                event.event_type.value,
                event.timestamp,
                event.tenant_id,
                event.user_id,
                event.request_id,
                event.entity_type,
                event.entity_count,
                event.strategy_used,
                event.source_ip,
                event.user_agent,
                event.api_key_hash,
                event.endpoint,
                event.method,
                event.status_code,
                event.error_message,
                event.risk_level.value,
                event.metadata,
            )

    async def write_batch(self, events: list[AuditEvent]) -> None:
        """批量写入审计事件"""
        await self._init()

        for event in events:
            await self.write(event)

    async def query(self, filter: AuditFilter) -> list[AuditEvent]:
        """查询审计事件"""
        await self._init()

        if self.db_type == "sqlite":
            return await self._query_sqlite(filter)
        else:
            return await self._query_postgresql(filter)

    def _build_query(self, filter: AuditFilter) -> tuple[str, list]:
        """构建查询 SQL"""
        conditions = ["timestamp >= ?", "timestamp <= ?"]
        params = [filter.start_date.isoformat(), filter.end_date.isoformat()]

        if filter.event_types:
            placeholders = ",".join("?" * len(filter.event_types))
            conditions.append(f"event_type IN ({placeholders})")
            params.extend([e.value for e in filter.event_types])

        if filter.tenant_id:
            conditions.append("tenant_id = ?")
            params.append(filter.tenant_id)

        if filter.user_id:
            conditions.append("user_id = ?")
            params.append(filter.user_id)

        if filter.request_id:
            conditions.append("request_id = ?")
            params.append(filter.request_id)

        if filter.risk_levels:
            placeholders = ",".join("?" * len(filter.risk_levels))
            conditions.append(f"risk_level IN ({placeholders})")
            params.extend([r.value for r in filter.risk_levels])

        where_clause = " AND ".join(conditions)

        order = "DESC" if filter.sort_order == "desc" else "ASC"
        query = f"""
            SELECT * FROM audit_logs
            WHERE {where_clause}
            ORDER BY {filter.sort_by} {order}
            LIMIT ? OFFSET ?
        """
        params.extend([filter.limit, filter.offset])

        return query, params

    async def _query_sqlite(self, filter: AuditFilter) -> list[AuditEvent]:
        """SQLite 查询"""
        query, params = self._build_query(filter)

        # 修改 SQLite 语法（使用 $1 风格占位符改为 ?）
        # 已经在上面构建好了

        rows = await self._pool.execute_fetchall(query, params)

        events = []
        for row in rows:
            # SQLite 返回的是元组，需要按列顺序获取
            event_dict = {
                "event_id": row[1],
                "event_type": row[2],
                "timestamp": row[3],
                "tenant_id": row[4],
                "user_id": row[5],
                "request_id": row[6],
                "entity_type": row[7],
                "entity_count": row[8],
                "strategy_used": row[9],
                "source_ip": row[10],
                "user_agent": row[11],
                "api_key_hash": row[12],
                "endpoint": row[13],
                "method": row[14],
                "status_code": row[15],
                "error_message": row[16],
                "risk_level": row[17],
            }
            try:
                event = AuditEvent.from_dict(event_dict)
                events.append(event)
            except (ValueError, KeyError):
                continue

        return events

    async def _query_postgresql(self, filter: AuditFilter) -> list[AuditEvent]:
        """PostgreSQL 查询"""
        # 需要重写构建查询方法以支持 PostgreSQL 语法
        conditions = ["timestamp >= $1", "timestamp <= $2"]
        params = [filter.start_date, filter.end_date]
        param_idx = 3

        if filter.event_types:
            placeholders = ",".join(f"${param_idx + i}" for i in range(len(filter.event_types)))
            conditions.append(f"event_type IN ({placeholders})")
            params.extend([e.value for e in filter.event_types])
            param_idx += len(filter.event_types)

        if filter.tenant_id:
            conditions.append(f"tenant_id = ${param_idx}")
            params.append(filter.tenant_id)
            param_idx += 1

        if filter.user_id:
            conditions.append(f"user_id = ${param_idx}")
            params.append(filter.user_id)
            param_idx += 1

        if filter.request_id:
            conditions.append(f"request_id = ${param_idx}")
            params.append(filter.request_id)
            param_idx += 1

        if filter.risk_levels:
            placeholders = ",".join(f"${param_idx + i}" for i in range(len(filter.risk_levels)))
            conditions.append(f"risk_level IN ({placeholders})")
            params.extend([r.value for r in filter.risk_levels])
            param_idx += len(filter.risk_levels)

        where_clause = " AND ".join(conditions)

        order = "DESC" if filter.sort_order == "desc" else "ASC"
        query = f"""
            SELECT
                event_id, event_type, timestamp, tenant_id, user_id, request_id,
                entity_type, entity_count, strategy_used, source_ip, user_agent,
                api_key_hash, endpoint, method, status_code, error_message,
                risk_level, metadata
            FROM audit_logs
            WHERE {where_clause}
            ORDER BY {filter.sort_by} {order}
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([filter.limit, filter.offset])

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        events = []
        for row in rows:
            event_dict = {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "timestamp": row["timestamp"].isoformat(),
                "tenant_id": row["tenant_id"],
                "user_id": row["user_id"],
                "request_id": row["request_id"],
                "entity_type": row["entity_type"],
                "entity_count": row["entity_count"],
                "strategy_used": row["strategy_used"],
                "source_ip": row["source_ip"],
                "user_agent": row["user_agent"],
                "api_key_hash": row["api_key_hash"],
                "endpoint": row["endpoint"],
                "method": row["method"],
                "status_code": row["status_code"],
                "error_message": row["error_message"],
                "risk_level": row["risk_level"],
                "metadata": row["metadata"] or {},
            }
            try:
                event = AuditEvent.from_dict(event_dict)
                events.append(event)
            except (ValueError, KeyError):
                continue

        return events

    async def export_json(
        self, filter: AuditFilter, *, pretty: bool = False
    ) -> str:
        """导出为 JSON 格式"""
        events = await self.query(filter)

        if pretty:
            return json.dumps([e.to_dict() for e in events], ensure_ascii=False, indent=2)
        return json.dumps([e.to_dict() for e in events], ensure_ascii=False)

    async def export_csv(self, filter: AuditFilter) -> str:
        """导出为 CSV 格式"""
        events = await self.query(filter)

        import io
        output = io.StringIO()
        fieldnames = [
            "event_id", "event_type", "timestamp", "tenant_id", "user_id",
            "request_id", "entity_type", "entity_count", "strategy_used",
            "source_ip", "endpoint", "method", "status_code", "risk_level",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            writer.writerow({
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "tenant_id": event.tenant_id or "",
                "user_id": event.user_id or "",
                "request_id": event.request_id or "",
                "entity_type": event.entity_type or "",
                "entity_count": event.entity_count,
                "strategy_used": event.strategy_used or "",
                "source_ip": event.source_ip or "",
                "endpoint": event.endpoint or "",
                "method": event.method or "",
                "status_code": event.status_code or "",
                "risk_level": event.risk_level.value,
            })

        return output.getvalue()

    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: Optional[str] = None,
    ) -> AuditSummary:
        """获取审计统计摘要"""
        filter = AuditFilter(
            start_date=start_date,
            end_date=end_date,
            tenant_id=tenant_id,
            limit=1000000,  # 大限制
        )
        events = await self.query(filter)

        summary = AuditSummary(
            period_start=start_date,
            period_end=end_date,
            tenant_id=tenant_id,
            total_events=len(events),
        )

        for event in events:
            summary.events_by_type[event.event_type.value] = (
                summary.events_by_type.get(event.event_type.value, 0) + 1
            )
            summary.events_by_risk[event.risk_level.value] = (
                summary.events_by_risk.get(event.risk_level.value, 0) + 1
            )

            if event.event_type == AuditEventType.PII_DETECTED:
                summary.pii_detected_count += event.entity_count
            elif event.event_type == AuditEventType.PII_ANONYMIZED:
                summary.pii_anonymized_count += event.entity_count

        return summary

    async def cleanup_old_logs(self, retention_days: int) -> int:
        """清理旧日志"""
        await self._init()

        cutoff_date = datetime.now() - timedelta(days=retention_days)

        if self.db_type == "sqlite":
            cursor = await self._pool.execute(
                "DELETE FROM audit_logs WHERE timestamp < ?", (cutoff_date.isoformat(),)
            )
            return cursor.rowcount
        else:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM audit_logs WHERE timestamp < $1", cutoff_date
                )
                return result.split()[-1]  # 返回受影响的行数

    async def close(self):
        """关闭数据库连接"""
        if self._pool:
            if self.db_type == "sqlite":
                await self._pool.close()
            else:
                await self._pool.close()
        self._initialized = False


# 全局单例
_audit_store: Optional[AuditStore] = None
_store_lock = asyncio.Lock()


async def get_audit_store() -> AuditStore:
    """获取审计存储实例（单例）

    支持通过环境变量 PII_AIRLOCK_AUDIT_STORE 配置存储后端:
    - memory: 内存存储（默认，测试环境）
    - file: 文件存储（开发环境）
    - redis: Redis 存储（生产环境）
    - database: 数据库存储（生产环境）
    """
    global _audit_store

    async with _store_lock:
        if _audit_store is None:
            import os

            store_type = os.getenv("PII_AIRLOCK_AUDIT_STORE", "file").lower()

            if store_type == "memory":
                max_events = int(os.getenv("PII_AIRLOCK_AUDIT_MAX_EVENTS", "10000"))
                _audit_store = MemoryAuditStore(max_events=max_events)
            elif store_type == "redis":
                import redis
                redis_url = os.getenv("PII_AIRLOCK_REDIS_URL", "redis://localhost:6379")
                redis_client = redis.from_url(redis_url, decode_responses=True)
                ttl = int(os.getenv("PII_AIRLOCK_AUDIT_TTL", "2592000"))  # 30 days
                _audit_store = RedisAuditStore(redis_client, default_ttl=ttl)
            elif store_type == "database":
                db_url = os.getenv("PII_AIRLOCK_AUDIT_DB_URL", "sqlite:///./audit.db")
                _audit_store = DatabaseAuditStore(db_url)
            else:  # file
                log_dir = os.getenv("PII_AIRLOCK_AUDIT_PATH", "./logs/audit")
                _audit_store = FileAuditStore(log_dir=log_dir)

        return _audit_store


class MemoryAuditStore(AuditStore):
    """内存审计日志存储

    适用于测试和开发环境。
    数据存储在内存中，服务重启后丢失。
    """

    def __init__(self, max_events: int = 10000):
        """初始化内存审计存储

        Args:
            max_events: 最大事件数量（超过后使用 FIFO 淘汰）
        """
        self._events: list[AuditEvent] = []
        self._max_events = max_events
        self._lock = asyncio.Lock()

    async def write(self, event: AuditEvent) -> None:
        """写入审计事件"""
        async with self._lock:
            self._events.append(event)
            # FIFO 淘汰
            if len(self._events) > self._max_events:
                self._events.pop(0)

    async def write_batch(self, events: list[AuditEvent]) -> None:
        """批量写入审计事件"""
        async with self._lock:
            self._events.extend(events)
            # FIFO 淘汰
            while len(self._events) > self._max_events:
                self._events.pop(0)

    async def query(self, filter: AuditFilter) -> list[AuditEvent]:
        """查询审计事件"""
        async with self._lock:
            # 过滤
            filtered = [
                e for e in self._events
                if filter.match(e)
            ]

            # 排序
            reverse = filter.sort_order == "desc"
            filtered.sort(key=lambda e: getattr(e, filter.sort_by), reverse=reverse)

            # 分页
            offset = filter.offset
            limit = filter.limit
            return filtered[offset:offset + limit]

    async def export_json(
        self, filter: AuditFilter, *, pretty: bool = False
    ) -> str:
        """导出为 JSON 格式"""
        events = await self.query(filter)

        if pretty:
            return json.dumps([e.to_dict() for e in events], ensure_ascii=False, indent=2)
        return json.dumps([e.to_dict() for e in events], ensure_ascii=False)

    async def export_csv(self, filter: AuditFilter) -> str:
        """导出为 CSV 格式"""
        events = await self.query(filter)

        import io
        output = io.StringIO()
        fieldnames = [
            "event_id", "event_type", "timestamp", "tenant_id", "user_id",
            "request_id", "entity_type", "entity_count", "strategy_used",
            "source_ip", "endpoint", "method", "status_code", "risk_level",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            writer.writerow({
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "tenant_id": event.tenant_id or "",
                "user_id": event.user_id or "",
                "request_id": event.request_id or "",
                "entity_type": event.entity_type or "",
                "entity_count": event.entity_count,
                "strategy_used": event.strategy_used or "",
                "source_ip": event.source_ip or "",
                "endpoint": event.endpoint or "",
                "method": event.method or "",
                "status_code": event.status_code or "",
                "risk_level": event.risk_level.value,
            })

        return output.getvalue()

    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: Optional[str] = None,
    ) -> AuditSummary:
        """获取审计统计摘要"""
        filter = AuditFilter(
            start_date=start_date,
            end_date=end_date,
            tenant_id=tenant_id,
            limit=1000000,
        )
        events = await self.query(filter)

        summary = AuditSummary(
            period_start=start_date,
            period_end=end_date,
            tenant_id=tenant_id,
            total_events=len(events),
        )

        for event in events:
            summary.events_by_type[event.event_type.value] = (
                summary.events_by_type.get(event.event_type.value, 0) + 1
            )
            summary.events_by_risk[event.risk_level.value] = (
                summary.events_by_risk.get(event.risk_level.value, 0) + 1
            )

            if event.event_type == AuditEventType.PII_DETECTED:
                summary.pii_detected_count += event.entity_count
            elif event.event_type == AuditEventType.PII_ANONYMIZED:
                summary.pii_anonymized_count += event.entity_count

        return summary

    async def cleanup_old_logs(self, retention_days: int) -> int:
        """清理旧日志"""
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_count = 0

        async with self._lock:
            original_length = len(self._events)
            self._events = [
                e for e in self._events
                if e.timestamp >= cutoff_date
            ]
            deleted_count = original_length - len(self._events)

        return deleted_count

    def clear(self) -> None:
        """清空所有事件（用于测试）"""
        self._events.clear()


class RedisAuditStore(AuditStore):
    """Redis 审计日志存储

    适用于生产环境和分布式部署。
    支持自动 TTL 过期和批量操作。
    """

    KEY_PREFIX = "pii_airlock:audit:"

    def __init__(
        self,
        redis_client,
        default_ttl: int = 2592000,  # 30 days default
    ):
        """初始化 Redis 审计存储

        Args:
            redis_client: Redis 客户端实例
            default_ttl: 默认 TTL（秒），默认 30 天
        """
        self._client = redis_client
        self._default_ttl = default_ttl

    def _make_key(self, event_id: str) -> str:
        """生成 Redis key"""
        return f"{self.KEY_PREFIX}{event_id}"

    async def write(self, event: AuditEvent) -> None:
        """写入审计事件"""
        key = self._make_key(event.event_id)
        data = event.to_json()

        # 使用 setex 设置 TTL
        self._client.setex(key, self._default_ttl, data)

        # 添加到时间索引（用于范围查询）
        timestamp_key = f"{self.KEY_PREFIX}timestamp:{int(event.timestamp.timestamp())}"
        self._client.sadd(timestamp_key, event.event_id)
        self._client.expire(timestamp_key, self._default_ttl)

    async def write_batch(self, events: list[AuditEvent]) -> None:
        """批量写入审计事件"""
        pipe = self._client.pipeline()

        for event in events:
            key = self._make_key(event.event_id)
            data = event.to_json()
            pipe.setex(key, self._default_ttl, data)

            timestamp_key = f"{self.KEY_PREFIX}timestamp:{int(event.timestamp.timestamp())}"
            pipe.sadd(timestamp_key, event.event_id)
            pipe.expire(timestamp_key, self._default_ttl)

        pipe.execute()

    async def query(self, filter: AuditFilter) -> list[AuditEvent]:
        """查询审计事件"""
        events = []

        # 扫描时间范围内的所有时间戳 key
        start_ts = int(filter.start_date.timestamp())
        end_ts = int(filter.end_date.timestamp())

        event_ids = set()
        for ts in range(start_ts, end_ts + 86400, 86400):  # 按天扫描
            timestamp_key = f"{self.KEY_PREFIX}timestamp:{ts}"
            members = self._client.smembers(timestamp_key)
            if members:
                event_ids.update(members)

        # 批量获取事件
        if event_ids:
            pipe = self._client.pipeline()
            for event_id in event_ids:
                pipe.get(self._make_key(event_id.decode() if isinstance(event_id, bytes) else event_id))

            results = pipe.execute()

            for data in results:
                if data:
                    try:
                        event = AuditEvent.from_json(
                            data.decode() if isinstance(data, bytes) else data
                        )
                        if filter.match(event):
                            events.append(event)
                    except (json.JSONDecodeError, ValueError):
                        continue

        # 排序
        reverse = filter.sort_order == "desc"
        events.sort(key=lambda e: getattr(e, filter.sort_by), reverse=reverse)

        # 分页
        offset = filter.offset
        limit = filter.limit
        return events[offset:offset + limit]

    async def export_json(
        self, filter: AuditFilter, *, pretty: bool = False
    ) -> str:
        """导出为 JSON 格式"""
        events = await self.query(filter)

        if pretty:
            return json.dumps([e.to_dict() for e in events], ensure_ascii=False, indent=2)
        return json.dumps([e.to_dict() for e in events], ensure_ascii=False)

    async def export_csv(self, filter: AuditFilter) -> str:
        """导出为 CSV 格式"""
        events = await self.query(filter)

        import io
        output = io.StringIO()
        fieldnames = [
            "event_id", "event_type", "timestamp", "tenant_id", "user_id",
            "request_id", "entity_type", "entity_count", "strategy_used",
            "source_ip", "endpoint", "method", "status_code", "risk_level",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            writer.writerow({
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "tenant_id": event.tenant_id or "",
                "user_id": event.user_id or "",
                "request_id": event.request_id or "",
                "entity_type": event.entity_type or "",
                "entity_count": event.entity_count,
                "strategy_used": event.strategy_used or "",
                "source_ip": event.source_ip or "",
                "endpoint": event.endpoint or "",
                "method": event.method or "",
                "status_code": event.status_code or "",
                "risk_level": event.risk_level.value,
            })

        return output.getvalue()

    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: Optional[str] = None,
    ) -> AuditSummary:
        """获取审计统计摘要"""
        filter = AuditFilter(
            start_date=start_date,
            end_date=end_date,
            tenant_id=tenant_id,
            limit=1000000,
        )
        events = await self.query(filter)

        summary = AuditSummary(
            period_start=start_date,
            period_end=end_date,
            tenant_id=tenant_id,
            total_events=len(events),
        )

        for event in events:
            summary.events_by_type[event.event_type.value] = (
                summary.events_by_type.get(event.event_type.value, 0) + 1
            )
            summary.events_by_risk[event.risk_level.value] = (
                summary.events_by_risk.get(event.risk_level.value, 0) + 1
            )

            if event.event_type == AuditEventType.PII_DETECTED:
                summary.pii_detected_count += event.entity_count
            elif event.event_type == AuditEventType.PII_ANONYMIZED:
                summary.pii_anonymized_count += event.entity_count

        return summary

    async def cleanup_old_logs(self, retention_days: int) -> int:
        """清理旧日志（依赖 Redis TTL 自动清理）"""
        # Redis 的 TTL 会自动清理过期数据
        # 这里只返回信息
        return 0


def set_audit_store(store: AuditStore) -> None:
    """设置审计存储实例（用于测试）"""
    global _audit_store
    _audit_store = store
