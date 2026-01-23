"""
仿真数据生成器基类

提供通用的哈希计算功能，确保所有生成器使用一致的确定性算法。
"""

import hashlib
from abc import ABC


class BaseSyntheticGenerator(ABC):
    """仿真数据生成器基类

    提供确定性哈希计算，确保同一输入在相同种子下总是产生相同输出。

    Attributes:
        seed: 随机种子，用于确定性生成
    """

    def __init__(self, *, seed: int = 42):
        """初始化生成器

        Args:
            seed: 随机种子（用于确定性生成）
        """
        self.seed = seed

    def _hash_string(self, s: str) -> int:
        """计算字符串的确定性哈希值

        使用 MD5 算法结合种子生成稳定的哈希值，
        确保相同输入和种子总是产生相同输出。

        Args:
            s: 待哈希的字符串

        Returns:
            哈希值（非负整数）
        """
        combined = f"{self.seed}:{s}"
        return int(hashlib.md5(combined.encode()).hexdigest(), 16)
