"""
中文姓名生成器

生成逼真的中文姓名，用于 PII 脱敏时替换真实姓名。

特性:
- 常见姓氏（基于中国人口统计）
- 真实名字用字
- 保持性别倾向（可选）
- 确定性生成（同一输入总是产生相同输出）
"""

import hashlib
from typing import Literal
from dataclasses import dataclass


# 常见姓氏（按人口比例排序）
COMMON_SURNAMES = [
    # 前20大姓 (占人口约50%)
    "王", "李", "张", "刘", "陈",
    "杨", "黄", "赵", "吴", "周",
    "徐", "孙", "马", "朱", "胡",
    "郭", "何", "高", "林", "罗",
    # 次常见姓氏
    "梁", "宋", "郑", "谢", "韩",
    "唐", "冯", "于", "董", "萧",
    "程", "曹", "袁", "邓", "许",
    "傅", "沈", "曾", "彭", "吕",
    "苏", "卢", "蒋", "蔡", "贾",
    "丁", "魏", "薛", "叶", "阎",
    # 复姓
    "欧阳", "太史", "端木", "上官", "司马",
    "东方", "独孤", "南宫", "万俟", "闻人",
    "夏侯", "诸葛", "尉迟", "公羊", "赫连",
    "澹台", "皇甫", "宗政", "濮阳", "公淳",
    "单于", "太叔", "申屠", "公孙", "仲孙",
    "轩辕", "令狐", "钟离", "宇文", "长孙",
    "慕容", "鲜于", "闾丘", "司徒", "司空",
]

# 常见男性用字
MALE_CHARS = [
    "伟", "强", "磊", "洋", "勇", "军", "杰", "涛", "超", "明",
    "刚", "平", "辉", "鹏", "华", "飞", "鑫", "波", "斌", "宇",
    "建国", "建军", "国强", "志强", "卫民", "勇", "国庆", "文杰",
    "浩", "然", "博", "文", "宇", "昊", "天", "铭", "轩", "睿",
]

# 常见女性用字
FEMALE_CHARS = [
    "静", "丽", "娟", "燕", "艳", "梅", "玲", "芳", "娜", "敏",
    "洁", "红", "霞", "萍", "玲", "婷", "雪", "慧", "颖", "琳",
    "玉兰", "桂英", "秀英", "淑珍", "海燕", "丽", "秀兰", "晓丽",
    "欣", "怡", "梦", "瑶", "萱", "菲", "琪", "妍", "薇", "倩",
]

# 中性用字
NEUTRAL_CHARS = [
    "子", "小", "晓", "思", "嘉", "雨", "新", "一", "之", "文",
    "云", "月", "星", "天", "可", "安", "宁", "欣", "然", "如",
]


@dataclass
class NameGenerationResult:
    """姓名生成结果"""
    original: str
    synthetic: str
    surname: str
    given_name: str
    is_compound: bool  # 是否复姓


class NameGenerator:
    """中文姓名生成器

    使用确定性算法生成逼真的中文姓名，确保同一输入总是产生相同输出。

    Example:
        >>> gen = NameGenerator()
        >>> result = gen.generate("张三")
        >>> print(result.synthetic)
        李明
        >>> result2 = gen.generate("张三")
        >>> assert result.synthetic == result2.synthetic  # 确定性
    """

    def __init__(
        self,
        *,
        preserve_gender: bool = False,
        preserve_compound: bool = True,
        seed: int = 42,
    ):
        """初始化姓名生成器

        Args:
            preserve_gender: 是否尝试保持性别倾向
            preserve_compound: 复姓是否替换为复姓
            seed: 随机种子（用于确定性生成）
        """
        self.preserve_gender = preserve_gender
        self.preserve_compound = preserve_compound
        self.seed = seed

    def generate(
        self,
        original: str,
        gender: Literal["male", "female", "unknown"] = "unknown",
    ) -> NameGenerationResult:
        """生成仿真姓名

        Args:
            original: 原始姓名
            gender: 性别（如果 preserve_gender=True 且已知性别）

        Returns:
            NameGenerationResult 包含生成的姓名和元数据
        """
        if not original or len(original) < 2:
            return NameGenerationResult(
                original=original,
                synthetic=original,
                surname="",
                given_name="",
                is_compound=False,
            )

        # 解析原姓名
        parsed = self._parse_name(original)
        surname = parsed["surname"]
        given_name = parsed["given_name"]
        is_compound = parsed["is_compound"]
        original_length = len(given_name)

        # 生成新姓氏
        new_surname = self._generate_surname(surname, is_compound)

        # 生成新名字
        gender_hint = gender if self.preserve_gender else "unknown"
        new_given_name = self._generate_given_name(
            original, given_name, original_length, gender_hint
        )

        synthetic = new_surname + new_given_name

        return NameGenerationResult(
            original=original,
            synthetic=synthetic,
            surname=new_surname,
            given_name=new_given_name,
            is_compound=is_compound,
        )

    def _parse_name(self, name: str) -> dict:
        """解析姓名，提取姓氏和名字"""
        name = name.strip()

        # 复姓列表（在 COMMON_SURNAMES 的后面部分）
        compound_surnames = COMMON_SURNAMES[100:] if len(COMMON_SURNAMES) > 100 else [
            "欧阳", "太史", "端木", "上官", "司马",
            "东方", "独孤", "南宫", "万俟", "闻人",
            "夏侯", "诸葛", "尉迟", "公羊", "赫连",
            "澹台", "皇甫", "宗政", "濮阳", "公淳",
            "单于", "太叔", "申屠", "公孙", "仲孙",
            "轩辕", "令狐", "钟离", "宇文", "长孙",
            "慕容", "鲜于", "闾丘", "司徒", "司空",
        ]

        # 检查复姓（先检查长的复姓）
        for compound in sorted(compound_surnames, key=len, reverse=True):
            if name.startswith(compound):
                return {
                    "surname": compound,
                    "given_name": name[len(compound):],
                    "is_compound": True,
                }

        # 单姓
        if len(name) >= 2:
            return {
                "surname": name[0],
                "given_name": name[1:],
                "is_compound": False,
            }

        # 无法解析
        return {
            "surname": "",
            "given_name": name,
            "is_compound": False,
        }

    def _generate_surname(self, original: str, is_compound: bool) -> str:
        """生成新姓氏"""
        # 使用原姓氏的哈希值选择新姓氏
        hash_val = self._hash_string(original)

        # 复姓列表
        compound_surnames = [
            "欧阳", "太史", "端木", "上官", "司马",
            "东方", "独孤", "南宫", "万俟", "闻人",
            "夏侯", "诸葛", "尉迟", "公羊", "赫连",
            "澹台", "皇甫", "宗政", "濮阳", "公淳",
            "单于", "太叔", "申屠", "公孙", "仲孙",
            "轩辕", "令狐", "钟离", "宇文", "长孙",
            "慕容", "鲜于", "闾丘", "司徒", "司空",
        ]

        if is_compound and self.preserve_compound:
            # 复姓替换为复姓
            idx = hash_val % len(compound_surnames)
            return compound_surnames[idx]
        else:
            # 单姓或普通替换
            # 倾向于使用常见姓氏（前50个）
            common = COMMON_SURNAMES[:50]
            if is_compound:
                # 复姓替换为单姓
                idx = hash_val % len(common)
                return common[idx]
            else:
                idx = hash_val % len(common)
                return common[idx]

    def _generate_given_name(
        self,
        original_full: str,
        given_name: str,
        length: int,
        gender: Literal["male", "female", "unknown"],
    ) -> str:
        """生成新名字"""
        hash_val = self._hash_string(original_full + given_name)

        # 根据长度选择生成策略
        if length == 1:
            # 单字名
            return self._select_single_char(gender, hash_val)
        elif length == 2:
            # 双字名
            return self._select_double_char(gender, hash_val)
        else:
            # 三个字及以上（较罕见）
            result = ""
            for i in range(length):
                h = (hash_val + i * 31) % (1 << 32)
                result += self._select_single_char("unknown", h)
            return result

    def _select_single_char(
        self,
        gender: Literal["male", "female", "unknown"],
        hash_val: int,
    ) -> str:
        """选择单个字"""
        if gender == "male":
            chars = MALE_CHARS + NEUTRAL_CHARS
        elif gender == "female":
            chars = FEMALE_CHARS + NEUTRAL_CHARS
        else:
            # 混合所有字符，但双字名权重更高
            chars = MALE_CHARS + FEMALE_CHARS + NEUTRAL_CHARS * 2

        idx = hash_val % len(chars)
        char = chars[idx]

        # 如果选中的是多字名，取第一个字
        return char[0] if len(char) > 1 else char

    def _select_double_char(
        self,
        gender: Literal["male", "female", "unknown"],
        hash_val: int,
    ) -> str:
        """选择两个字组成名字"""
        h1 = hash_val
        h2 = (hash_val * 31 + 17) % (1 << 32)

        # 第一个字倾向使用中性或常用字
        char1 = self._select_single_char("unknown", h1)

        # 第二个字根据性别选择
        char2 = self._select_single_char(gender, h2)

        # 避免两个字相同（除非是特意为之）
        if char1 == char2:
            h2 = (h2 + 1) % (1 << 32)
            char2 = self._select_single_char(gender, h2)

        return char1 + char2

    def _hash_string(self, s: str) -> int:
        """计算字符串的确定性哈希值"""
        # 结合固定种子确保跨会话一致性
        combined = f"{self.seed}:{s}"
        return int(hashlib.md5(combined.encode()).hexdigest(), 16)

    def is_valid_name(self, name: str) -> bool:
        """检查是否是有效的中文姓名

        Args:
            name: 要检查的姓名

        Returns:
            是否是有效的中文姓名
        """
        if not name or len(name) < 2 or len(name) > 4:
            return False

        # 检查是否包含中文字符
        if not all("\u4e00" <= c <= "\u9fff" for c in name):
            return False

        return True
