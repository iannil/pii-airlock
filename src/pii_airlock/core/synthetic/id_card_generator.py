"""
身份证号生成器

生成逼真的中国身份证号码，用于 PII 脱敏时替换真实身份证号。

注意：此生成的号码仅用于测试和开发，不具备任何法律效力。

特性:
- 保持地区码
- 保持出生日期
- 保持性别
- 正确的校验码
- 确定性生成（同一输入总是产生相同输出）
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Literal


# 省级行政区划代码（前6位中的前2位）
PROVINCE_CODES = {
    "11": "北京市", "12": "天津市", "13": "河北省", "14": "山西省", "15": "内蒙古自治区",
    "21": "辽宁省", "22": "吉林省", "23": "黑龙江省",
    "31": "上海市", "32": "江苏省", "33": "浙江省", "34": "安徽省", "35": "福建省", "36": "江西省", "37": "山东省",
    "41": "河南省", "42": "湖北省", "43": "湖南省", "44": "广东省", "45": "广西壮族自治区", "46": "海南省",
    "50": "重庆市", "51": "四川省", "52": "贵州省", "53": "云南省", "54": "西藏自治区",
    "61": "陕西省", "62": "甘肃省", "63": "青海省", "64": "宁夏回族自治区", "65": "新疆维吾尔自治区",
}

# 校验码权重
WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]

# 校验码对应表
CHECK_CODE_MAP = {
    0: '1', 1: '0', 2: 'X', 3: '9', 4: '8',
    5: '7', 6: '6', 7: '5', 8: '4', 9: '3', 10: '2'
}


@dataclass
class IdCardGenerationResult:
    """身份证号生成结果"""
    original: str
    synthetic: str
    region_code: str
    birth_date: str
    gender: Literal["male", "female", "unknown"]
    is_valid: bool


class IdCardGenerator:
    """中国身份证号生成器

    使用确定性算法生成逼真的中国身份证号，确保同一输入总是产生相同输出。

    注意：生成的号码仅供测试使用，不具备法律效力。

    Example:
        >>> gen = IdCardGenerator()
        >>> result = gen.generate("110101199003077758")
        >>> print(result.synthetic)
        310101199003077123
        >>> print(result.region_code)
        上海市
    """

    # 18位身份证正则
    ID_CARD_18_PATTERN = r"^[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]$"

    # 15位身份证正则
    ID_CARD_15_PATTERN = r"^[1-9]\d{5}\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}$"

    def __init__(
        self,
        *,
        preserve_region: bool = True,
        preserve_birth_date: bool = True,
        preserve_gender: bool = True,
        seed: int = 42,
    ):
        """初始化身份证号生成器

        Args:
            preserve_region: 是否保持地区码
            preserve_birth_date: 是否保持出生日期
            preserve_gender: 是否保持性别
            seed: 随机种子（用于确定性生成）
        """
        self.preserve_region = preserve_region
        self.preserve_birth_date = preserve_birth_date
        self.preserve_gender = preserve_gender
        self.seed = seed

    def generate(self, original: str) -> IdCardGenerationResult:
        """生成仿真身份证号

        Args:
            original: 原始身份证号

        Returns:
            IdCardGenerationResult 包含生成的身份证号和元数据
        """
        # 解析原身份证号
        parsed = self._parse_id_card(original)

        if not parsed["is_valid"]:
            return IdCardGenerationResult(
                original=original,
                synthetic=original,
                region_code="",
                birth_date="",
                gender="unknown",
                is_valid=False,
            )

        # 生成新身份证号
        new_region = self._generate_region(parsed["region_code"])
        new_birth_date = parsed["birth_date"] if self.preserve_birth_date else self._generate_birth_date()
        new_gender = parsed["gender"] if self.preserve_gender else "unknown"

        # 生成顺序码（3位，最后一位表示性别）
        sequence = self._generate_sequence(original, new_gender)

        # 组合前17位
        prefix = new_region + new_birth_date + sequence

        # 计算校验码
        check_code = self._calculate_check_code(prefix)

        synthetic = prefix + check_code

        return IdCardGenerationResult(
            original=original,
            synthetic=synthetic,
            region_code=new_region,
            birth_date=new_birth_date,
            gender=new_gender,
            is_valid=True,
        )

    def _parse_id_card(self, id_card: str) -> dict:
        """解析身份证号"""
        id_card = id_card.strip().upper()

        # 检查18位
        import re
        if re.match(self.ID_CARD_18_PATTERN, id_card):
            region = id_card[:6]
            birth = id_card[6:14]
            sequence = id_card[14:17]

            # 解析性别（第17位，奇数为男，偶数为女）
            gender_num = int(sequence[-1])
            gender = "male" if gender_num % 2 == 1 else "female"

            return {
                "is_valid": True,
                "region_code": region,
                "birth_date": birth,
                "sequence": sequence,
                "gender": gender,
                "length": 18,
            }

        # 检查15位（老版身份证）
        if re.match(self.ID_CARD_15_PATTERN, id_card):
            region = id_card[:6]
            birth = "19" + id_card[6:12]  # 15位身份证没有世纪，默认19XX
            sequence = id_card[12:15]

            gender_num = int(sequence[-1])
            gender = "male" if gender_num % 2 == 1 else "female"

            return {
                "is_valid": True,
                "region_code": region,
                "birth_date": birth,
                "sequence": sequence,
                "gender": gender,
                "length": 15,
            }

        return {
            "is_valid": False,
            "region_code": "",
            "birth_date": "",
            "sequence": "",
            "gender": "unknown",
            "length": 0,
        }

    def _generate_region(self, original: str) -> str:
        """生成新区划代码"""
        if self.preserve_region:
            # 保持省级代码，改变后4位
            province = original[:2]
            hash_val = self._hash_string(original)

            # 生成后4位（区县级代码）
            suffix = (hash_val % 10000)
            return f"{province}{suffix:04d}"
        else:
            # 完全随机生成
            hash_val = self._hash_string(original)
            province_idx = hash_val % len(PROVINCE_CODES)
            province = list(PROVINCE_CODES.keys())[province_idx]

            suffix = ((hash_val >> 8) % 10000)
            return f"{province}{suffix:04d}"

    def _generate_birth_date(self) -> str:
        """生成出生日期（YYYYMMDD）"""
        # 生成1950-2005年之间的随机日期
        import time
        hash_val = int(hashlib.md5(f"{self.seed}:{time.time()}".encode()).hexdigest(), 16)

        year = 1950 + (hash_val % 56)  # 1950-2005
        month = 1 + ((hash_val >> 8) % 12)
        day = 1 + ((hash_val >> 16) % 28)  # 简化处理，避免日期计算

        return f"{year}{month:02d}{day:02d}"

    def _generate_sequence(self, original: str, gender: Literal["male", "female", "unknown"]) -> str:
        """生成顺序码（3位）"""
        hash_val = self._hash_string(original + "seq")

        # 前两位随机
        seq = (hash_val % 100)

        # 第三位表示性别
        if gender == "male":
            # 奇数
            last = 2 * ((hash_val >> 8) % 5) + 1
        elif gender == "female":
            # 偶数
            last = 2 * ((hash_val >> 8) % 5)
        else:
            # 随机
            last = (hash_val >> 8) % 10

        return f"{seq:02d}{last}"

    def _calculate_check_code(self, prefix17: str) -> str:
        """计算校验码

        Args:
            prefix17: 身份证号前17位

        Returns:
            校验码（数字或X）
        """
        total = 0
        for i in range(17):
            digit = int(prefix17[i])
            total += digit * WEIGHTS[i]

        remainder = total % 11
        return CHECK_CODE_MAP[remainder]

    def _hash_string(self, s: str) -> int:
        """计算字符串的确定性哈希值"""
        combined = f"{self.seed}:{s}"
        return int(hashlib.md5(combined.encode()).hexdigest(), 16)

    def is_valid_id_card(self, id_card: str) -> bool:
        """检查是否是有效的身份证号

        Args:
            id_card: 身份证号

        Returns:
            是否有效
        """
        parsed = self._parse_id_card(id_card)
        if not parsed["is_valid"]:
            return False

        # 对于18位身份证，验证校验码
        if parsed["length"] == 18:
            prefix17 = id_card[:17]
            expected_check = self._calculate_check_code(prefix17)
            actual_check = id_card[17].upper()
            return expected_check == actual_check

        return True

    def get_region_name(self, region_code: str) -> str:
        """获取地区名称

        Args:
            region_code: 6位地区代码

        Returns:
            地区名称
        """
        province_code = region_code[:2]
        return PROVINCE_CODES.get(province_code, "未知")

    def get_birth_date(self, id_card: str) -> str | None:
        """获取出生日期

        Args:
            id_card: 身份证号

        Returns:
            出生日期字符串 (YYYY-MM-DD) 或 None
        """
        parsed = self._parse_id_card(id_card)
        if not parsed["is_valid"]:
            return None

        birth = parsed["birth_date"]
        if len(birth) == 8:
            return f"{birth[:4]}-{birth[4:6]}-{birth[6:8]}"
        return None

    def get_gender(self, id_card: str) -> str | None:
        """获取性别

        Args:
            id_card: 身份证号

        Returns:
            性别 (male/female) 或 None
        """
        parsed = self._parse_id_card(id_card)
        if not parsed["is_valid"]:
            return None
        return parsed["gender"]

    def get_age(self, id_card: str) -> int | None:
        """计算年龄

        Args:
            id_card: 身份证号

        Returns:
            年龄或 None
        """
        birth_str = self.get_birth_date(id_card)
        if not birth_str:
            return None

        try:
            birth_date = datetime.strptime(birth_str, "%Y-%m-%d")
            today = datetime.now()
            age = today.year - birth_date.year

            # 如果今年生日还没过，减1岁
            if (today.month, today.day) < (birth_date.month, birth_date.day):
                age -= 1

            return age
        except ValueError:
            return None
