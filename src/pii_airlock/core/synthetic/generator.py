"""
仿真数据生成器

统一的仿真数据生成接口，整合各种 PII 类型的生成器。
"""

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from pii_airlock.core.synthetic.name_generator import NameGenerator
from pii_airlock.core.synthetic.phone_generator import PhoneGenerator
from pii_airlock.core.synthetic.email_generator import EmailGenerator
from pii_airlock.core.synthetic.id_card_generator import IdCardGenerator


@dataclass
class SyntheticMapping:
    """仿真数据映射

    记录原始值和仿真值的对应关系，用于回填时还原。
    """
    original: str
    synthetic: str
    entity_type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"SyntheticMapping({self.entity_type}: {self.original[:3]}*** → {self.synthetic[:3]}***)"


@dataclass
class SyntheticResult:
    """仿真数据生成结果"""
    text: str  # 处理后的文本
    mappings: list[SyntheticMapping]  # 映射列表
    replaced_count: int  # 替换数量

    def get_synthetic_for(self, original: str) -> str | None:
        """获取给定原始值的仿真值"""
        for m in self.mappings:
            if m.original == original:
                return m.synthetic
        return None

    def get_original_for(self, synthetic: str) -> str | None:
        """获取仿真值对应的原始值"""
        for m in self.mappings:
            if m.synthetic == synthetic:
                return m.original
        return None


class SyntheticDataGenerator:
    """仿真数据生成器

    整合各种 PII 类型的生成器，提供统一的生成接口。

    Example:
        >>> gen = SyntheticDataGenerator()
        >>> result = gen.anonymize("张三的电话是13800138000")
        >>> print(result.text)
        李四的电话是13912345678
        >>> # 可以通过 mappings 还原
        >>> for m in result.mappings:
        ...     print(f"{m.original} → {m.synthetic}")
        张三 → 李四
        13800138000 → 13912345678
    """

    def __init__(
        self,
        *,
        seed: Optional[int] = None,
        session_id: Optional[str] = None,
        name_preserve_gender: bool = False,
        phone_preserve_carrier: bool = True,
        id_preserve_region: bool = True,
        id_preserve_birth_date: bool = True,
        email_preserve_domain_type: bool = False,
    ):
        """初始化仿真数据生成器

        SEC-006 FIX: 添加会话隔离，使相同原始值在不同会话生成不同的仿真值。

        Args:
            seed: 随机种子（如果不提供，将基于 session_id 或随机生成）
            session_id: 会话标识（用于会话级别的隔离）
            name_preserve_gender: 姓名是否保持性别
            phone_preserve_carrier: 手机号是否保持运营商
            id_preserve_region: 身份证是否保持地区码
            id_preserve_birth_date: 身份证是否保持出生日期
            email_preserve_domain_type: 邮箱是否保持域名类型
        """
        # SEC-006 FIX: 基于会话生成隔离的种子
        self.session_id = session_id or secrets.token_hex(8)

        if seed is not None:
            # 即使提供了 seed，也加入会话隔离
            session_hash = int(hashlib.sha256(self.session_id.encode()).hexdigest()[:8], 16)
            self.seed = (seed + session_hash) % (2**31)
        else:
            # 基于会话 ID 生成确定性种子
            self.seed = int(hashlib.sha256(self.session_id.encode()).hexdigest()[:8], 16)

        # SEC-006 FIX: 初始化各类型生成器时使用会话隔离的种子
        self.name_generator = NameGenerator(
            preserve_gender=name_preserve_gender,
            seed=self.seed,
        )
        self.phone_generator = PhoneGenerator(
            preserve_carrier=phone_preserve_carrier,
            seed=self.seed,
        )
        self.id_card_generator = IdCardGenerator(
            preserve_region=id_preserve_region,
            preserve_birth_date=id_preserve_birth_date,
            seed=self.seed,
        )
        self.email_generator = EmailGenerator(
            preserve_domain_type=email_preserve_domain_type,
            seed=self.seed,
        )

        # 映射缓存（确保同一输入产生相同输出）
        self._mapping_cache: dict[str, SyntheticMapping] = {}

    def generate(
        self,
        original: str,
        entity_type: str,
        **kwargs
    ) -> SyntheticMapping:
        """生成仿真数据

        Args:
            original: 原始 PII 值
            entity_type: PII 类型 (PERSON, PHONE, EMAIL, ID_CARD 等)
            **kwargs: 额外参数（如 gender 等）

        Returns:
            SyntheticMapping 包含原始值和仿真值的映射
        """
        # SEC-006 FIX: 缓存键包含会话 ID，确保会话隔离
        cache_key = f"{self.session_id}:{entity_type}:{original}:{kwargs}"
        if cache_key in self._mapping_cache:
            return self._mapping_cache[cache_key]

        # 根据类型选择生成器
        if entity_type in ("PERSON", "PERSON_NAME"):
            result = self._generate_name(original, **kwargs)
        elif entity_type in ("PHONE", "PHONE_NUMBER", "MOBILE"):
            result = self._generate_phone(original, **kwargs)
        elif entity_type in ("EMAIL", "EMAIL_ADDRESS"):
            result = self._generate_email(original, **kwargs)
        elif entity_type in ("ID_CARD", "IDENTITY_CARD", "CHINESE_ID_CARD"):
            result = self._generate_id_card(original, **kwargs)
        else:
            # 未知类型，返回原值
            result = SyntheticMapping(
                original=original,
                synthetic=original,
                entity_type=entity_type,
                metadata={"warning": "unknown_entity_type"},
            )

        # 缓存结果
        self._mapping_cache[cache_key] = result
        return result

    def _generate_name(self, original: str, **kwargs) -> SyntheticMapping:
        """生成仿真姓名"""
        gender = kwargs.get("gender", "unknown")
        name_result = self.name_generator.generate(original, gender=gender)

        return SyntheticMapping(
            original=original,
            synthetic=name_result.synthetic,
            entity_type="PERSON",
            metadata={
                "surname": name_result.surname,
                "given_name": name_result.given_name,
                "is_compound": name_result.is_compound,
            },
        )

    def _generate_phone(self, original: str, **kwargs) -> SyntheticMapping:
        """生成仿真手机号"""
        phone_result = self.phone_generator.generate(original)

        return SyntheticMapping(
            original=original,
            synthetic=phone_result.synthetic,
            entity_type="PHONE",
            metadata={
                "prefix": phone_result.prefix,
                "carrier": phone_result.carrier,
            },
        )

    def _generate_email(self, original: str, **kwargs) -> SyntheticMapping:
        """生成仿真邮箱"""
        email_result = self.email_generator.generate(original)

        return SyntheticMapping(
            original=original,
            synthetic=email_result.synthetic,
            entity_type="EMAIL",
            metadata={
                "username": email_result.username,
                "domain": email_result.domain,
                "pattern": email_result.pattern,
            },
        )

    def _generate_id_card(self, original: str, **kwargs) -> SyntheticMapping:
        """生成仿真身份证号"""
        id_result = self.id_card_generator.generate(original)

        return SyntheticMapping(
            original=original,
            synthetic=id_result.synthetic,
            entity_type="ID_CARD",
            metadata={
                "region_code": id_result.region_code,
                "birth_date": id_result.birth_date,
                "gender": id_result.gender,
                "is_valid": id_result.is_valid,
            },
        )

    def anonymize(
        self,
        text: str,
        detections: list[dict] | None = None,
    ) -> SyntheticResult:
        """对文本进行仿真数据脱敏

        Args:
            text: 原始文本
            detections: PII 检测结果列表，每个元素包含:
                - value: PII 值
                - entity_type: PII 类型
                - start: 开始位置
                - end: 结束位置

        Returns:
            SyntheticResult 包含处理后的文本和映射关系
        """
        if not detections:
            # 如果没有提供检测结果，返回原文本
            return SyntheticResult(
                text=text,
                mappings=[],
                replaced_count=0,
            )

        result_text = text
        mappings: list[SyntheticMapping] = []

        # 按位置倒序处理，避免位置偏移
        sorted_detections = sorted(
            detections,
            key=lambda d: d.get("start", 0),
            reverse=True,
        )

        for detection in sorted_detections:
            value = detection.get("value", "")
            entity_type = detection.get("entity_type", "")
            start = detection.get("start", 0)
            end = detection.get("end", 0)

            if not value or not entity_type:
                continue

            # 生成仿真数据
            mapping = self.generate(value, entity_type)

            # 替换文本
            if start < len(result_text) and end <= len(result_text):
                result_text = (
                    result_text[:start] +
                    mapping.synthetic +
                    result_text[end:]
                )
                mappings.append(mapping)

        return SyntheticResult(
            text=result_text,
            mappings=mappings,
            replaced_count=len(mappings),
        )

    def deanonymize(self, text: str, mappings: list[SyntheticMapping]) -> str:
        """使用映射关系还原文本

        Args:
            text: 包含仿真数据的文本
            mappings: 映射关系列表

        Returns:
            还原后的文本
        """
        result = text
        # 按长度降序排序，避免部分替换问题
        for mapping in sorted(mappings, key=lambda m: -len(m.synthetic)):
            result = result.replace(mapping.synthetic, mapping.original)
        return result

    def clear_cache(self) -> None:
        """清除映射缓存"""
        self._mapping_cache.clear()

    def get_cache_size(self) -> int:
        """获取缓存大小"""
        return len(self._mapping_cache)


# 全局单例 (仅用于不需要会话隔离的场景)
_synthetic_generator: SyntheticDataGenerator | None = None


def get_synthetic_generator(**kwargs) -> SyntheticDataGenerator:
    """获取全局仿真数据生成器实例

    注意：此函数返回全局单例，所有请求共享同一个生成器。
    如需会话隔离，请使用 create_session_generator() 函数。

    Args:
        **kwargs: 传递给 SyntheticDataGenerator 的参数

    Returns:
        SyntheticDataGenerator 实例
    """
    global _synthetic_generator

    if _synthetic_generator is None:
        _synthetic_generator = SyntheticDataGenerator(**kwargs)

    return _synthetic_generator


def create_session_generator(
    session_id: Optional[str] = None,
    **kwargs,
) -> SyntheticDataGenerator:
    """创建会话隔离的仿真数据生成器

    SEC-006 FIX: 每个会话使用独立的生成器，确保相同原始值
    在不同会话中生成不同的仿真值，防止逆向推导。

    Args:
        session_id: 会话标识。如果不提供，将自动生成随机 ID。
        **kwargs: 其他传递给 SyntheticDataGenerator 的参数

    Returns:
        新的 SyntheticDataGenerator 实例
    """
    return SyntheticDataGenerator(session_id=session_id, **kwargs)
