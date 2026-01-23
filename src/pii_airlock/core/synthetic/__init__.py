"""
仿真数据合成模块

提供语义相似的假数据生成功能，用于 PII 脱敏时保持数据上下文完整性。

主要组件:
- BaseSyntheticGenerator: 仿真数据生成器基类
- SyntheticDataGenerator: 仿真数据生成器
- NameGenerator: 中文姓名生成器
- PhoneGenerator: 手机号生成器
- EmailGenerator: 邮箱生成器
- IdCardGenerator: 身份证号生成器
"""

from pii_airlock.core.synthetic.base import BaseSyntheticGenerator
from pii_airlock.core.synthetic.name_generator import NameGenerator
from pii_airlock.core.synthetic.phone_generator import PhoneGenerator
from pii_airlock.core.synthetic.email_generator import EmailGenerator
from pii_airlock.core.synthetic.id_card_generator import IdCardGenerator
from pii_airlock.core.synthetic.generator import (
    SyntheticDataGenerator,
    SyntheticMapping,
    get_synthetic_generator,
)

__all__ = [
    "BaseSyntheticGenerator",
    "NameGenerator",
    "PhoneGenerator",
    "EmailGenerator",
    "IdCardGenerator",
    "SyntheticDataGenerator",
    "SyntheticMapping",
    "get_synthetic_generator",
]
