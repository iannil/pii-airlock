"""
手机号生成器

生成逼真的中国手机号码，用于 PII 脱敏时替换真实手机号。

特性:
- 使用真实运营商号段
- 保持运营商类型（移动/联通/电信）
- 确定性生成（同一输入总是产生相同输出）
- 可选地保持号段规律
"""

from dataclasses import dataclass
from typing import Literal

from pii_airlock.core.synthetic.base import BaseSyntheticGenerator


# 中国移动号段（前3位或前4位）
CHINA_MOBILE_PREFIXES = [
    # 134-139
    "134", "135", "136", "137", "138", "139",
    # 147, 148（物联网）
    "147", "148",
    # 150-152
    "150", "151", "152",
    # 157-159
    "157", "158", "159",
    # 172（物联网）
    "172",
    # 178, 182-184
    "178", "182", "183", "184",
    # 187-189
    "187", "188", "189",
    # 195, 197, 198
    "195", "197", "198",
]

# 中国联通号段
CHINA_UNICOM_PREFIXES = [
    # 130-132
    "130", "131", "132",
    # 145, 146（物联网）
    "145", "146",
    # 155, 156
    "155", "156",
    # 166
    "166",
    # 175, 176
    "175", "176",
    # 185, 186
    "185", "186",
    # 196
    "196",
]

# 中国电信号段
CHINA_TELECOM_PREFIXES = [
    # 133, 149, 153, 173, 177, 180, 181, 189, 190, 191, 193, 199
    "133", "149", "153", "173", "177", "180", "181", "189",
    "190", "191", "193", "199",
]

# 中国广电号段（新增）
CHINA_BROADCASTING_PREFIXES = [
    "192",
]

# 所有有效号段
ALL_VALID_PREFIXES = (
    CHINA_MOBILE_PREFIXES +
    CHINA_UNICOM_PREFIXES +
    CHINA_TELECOM_PREFIXES +
    CHINA_BROADCASTING_PREFIXES
)

# 号段归属映射
PREFIX_TO_CARRIER = {}
for p in CHINA_MOBILE_PREFIXES:
    PREFIX_TO_CARRIER[p] = "mobile"
for p in CHINA_UNICOM_PREFIXES:
    PREFIX_TO_CARRIER[p] = "unicom"
for p in CHINA_TELECOM_PREFIXES:
    PREFIX_TO_CARRIER[p] = "telecom"
for p in CHINA_BROADCASTING_PREFIXES:
    PREFIX_TO_CARRIER[p] = "broadcasting"


@dataclass
class PhoneGenerationResult:
    """手机号生成结果"""
    original: str
    synthetic: str
    prefix: str
    carrier: Literal["mobile", "unicom", "telecom", "broadcasting", "unknown"]


class PhoneGenerator(BaseSyntheticGenerator):
    """中国手机号生成器

    使用确定性算法生成逼真的中国手机号，确保同一输入总是产生相同输出。

    Example:
        >>> gen = PhoneGenerator()
        >>> result = gen.generate("13800138000")
        >>> print(result.synthetic)
        13912345678
        >>> print(result.carrier)
        mobile
    """

    def __init__(
        self,
        *,
        preserve_carrier: bool = True,
        preserve_prefix_length: bool = True,
        seed: int = 42,
    ):
        """初始化手机号生成器

        Args:
            preserve_carrier: 是否保持运营商类型
            preserve_prefix_length: 是否保持号段前3位
            seed: 随机种子（用于确定性生成）
        """
        super().__init__(seed=seed)
        self.preserve_carrier = preserve_carrier
        self.preserve_prefix_length = preserve_prefix_length

    def generate(self, original: str) -> PhoneGenerationResult:
        """生成仿真手机号

        Args:
            original: 原始手机号

        Returns:
            PhoneGenerationResult 包含生成的手机号和元数据
        """
        # 验证和解析原号码
        if not self._is_valid_phone(original):
            return PhoneGenerationResult(
                original=original,
                synthetic=original,
                prefix="",
                carrier="unknown",
            )

        # 提取前3位号段
        prefix = original[:3]
        original_carrier = PREFIX_TO_CARRIER.get(prefix, "unknown")

        # 生成新号段
        new_prefix = self._generate_prefix(prefix, original_carrier)
        new_carrier = PREFIX_TO_CARRIER.get(new_prefix, "unknown")

        # 生成后8位
        suffix = self._generate_suffix(original, new_prefix)

        synthetic = new_prefix + suffix

        return PhoneGenerationResult(
            original=original,
            synthetic=synthetic,
            prefix=new_prefix,
            carrier=new_carrier,
        )

    def _is_valid_phone(self, phone: str) -> bool:
        """检查是否是有效的中国手机号"""
        if not phone or len(phone) != 11:
            return False

        if not phone.isdigit():
            return False

        prefix = phone[:3]
        return prefix in ALL_VALID_PREFIXES

    def _generate_prefix(
        self,
        original_prefix: str,
        original_carrier: str,
    ) -> str:
        """生成新号段"""
        hash_val = self._hash_string(original_prefix)

        if self.preserve_carrier and original_carrier != "unknown":
            # 保持运营商
            if original_carrier == "mobile":
                candidates = CHINA_MOBILE_PREFIXES
            elif original_carrier == "unicom":
                candidates = CHINA_UNICOM_PREFIXES
            elif original_carrier == "telecom":
                candidates = CHINA_TELECOM_PREFIXES
            else:  # broadcasting
                candidates = CHINA_BROADCASTING_PREFIXES

            idx = hash_val % len(candidates)
            return candidates[idx]
        else:
            # 随机选择任意号段
            idx = hash_val % len(ALL_VALID_PREFIXES)
            return ALL_VALID_PREFIXES[idx]

    def _generate_suffix(self, original: str, new_prefix: str) -> str:
        """生成后8位"""
        # 使用原号码后8位作为哈希输入
        original_suffix = original[3:] if len(original) >= 11 else original
        hash_val = self._hash_string(new_prefix + original_suffix)

        # 生成8位数字
        suffix = ""
        for i in range(8):
            h = (hash_val + i * 17) % (1 << 32)
            digit = h % 10
            suffix += str(digit)

        return suffix

    def get_carrier(self, phone: str) -> str:
        """获取手机号所属运营商

        Args:
            phone: 手机号

        Returns:
            运营商名称 (mobile/unicom/telecom/broadcasting/unknown)
        """
        if len(phone) >= 3:
            prefix = phone[:3]
            return PREFIX_TO_CARRIER.get(prefix, "unknown")
        return "unknown"

    def format_phone(self, phone: str, format_type: Literal["plain", "space", "dash"] = "plain") -> str:
        """格式化手机号显示

        Args:
            phone: 手机号
            format_type: 格式类型 (plain/space/dash)

        Returns:
            格式化后的手机号
        """
        if len(phone) != 11:
            return phone

        if format_type == "space":
            return f"{phone[:3]} {phone[3:7]} {phone[7:]}"
        elif format_type == "dash":
            return f"{phone[:3]}-{phone[3:7]}-{phone[7:]}"
        else:
            return phone
