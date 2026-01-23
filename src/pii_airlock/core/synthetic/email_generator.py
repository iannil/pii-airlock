"""
邮箱生成器

生成逼真的邮箱地址，用于 PII 脱敏时替换真实邮箱。

特性:
- 常见邮箱域名
- 保持邮箱格式风格
- 确定性生成（同一输入总是产生相同输出）
"""

import re
from dataclasses import dataclass
from typing import Literal

from pii_airlock.core.synthetic.base import BaseSyntheticGenerator


# 常见邮箱域名（中文用户常用）
COMMON_DOMAINS = [
    # 国内主流
    "qq.com", "163.com", "126.com", "sina.com", "sohu.com",
    "aliyun.com", "foxmail.com", "outlook.com", "hotmail.com",
    # 企业邮箱
    "gmail.com", "icloud.com", "yeah.net",
    # 其他常见
    "139.com", "189.cn", "sina.cn", "vip.qq.com",
]

# 常用用户名前缀模式
USERNAME_PATTERNS = [
    "pinyin",       # 拼音全拼: zhangsan
    "pinyin_dot",   # 拼音加点: zhang.san
    "pinyin_num",   # 拼音加数字: zhangsan123
    "initial",      # 首字母: zs
    "mixed",        # 混合: zhang_san88
]

# 拼音音节（用于生成拼音用户名）
PINYIN_SYLLABLES = [
    "a", "ai", "an", "ang", "ao",
    "ba", "bai", "ban", "bang", "bao", "bei", "ben", "beng", "bi", "bian", "biao", "bie", "bin", "bing", "bo", "bu",
    "ca", "cai", "can", "cang", "cao", "ce", "cen", "ceng", "cha", "chai", "chan", "chang", "chao", "che", "chen",
    "cheng", "chi", "chong", "chou", "chu", "chua", "chuai", "chuan", "chuang", "chui", "chun", "chuo", "ci", "cong", "cou", "cu",
    "cua", "cuan", "cui", "cun", "cuo",
    "da", "dai", "dan", "dang", "dao", "de", "dei", "den", "deng", "di", "dia", "dian", "diao", "die", "ding", "diu", "dong",
    "dou", "du", "dua", "duan", "dui", "dun", "duo",
    "e", "ei", "en", "eng", "er",
    "fa", "fan", "fang", "fei", "fen", "feng", "fo", "fou", "fu",
    "ga", "gai", "gan", "gang", "gao", "ge", "gei", "gen", "geng", "gong", "gou", "gu", "gua", "guai", "guan", "guang",
    "gui", "gun", "guo",
    "ha", "hai", "han", "hang", "hao", "he", "hei", "hen", "heng", "hm", "hng", "hong", "hou", "hu", "hua", "huai",
    "huan", "huang", "hui", "hun", "huo",
    "ji", "jia", "jian", "jiang", "jiao", "jie", "jin", "jing", "jiong", "jiu", "ju", "juan", "jue", "jun",
    "ka", "kai", "kan", "kang", "kao", "ke", "ken", "keng", "kong", "kou", "ku", "kua", "kuai", "kuan", "kuang",
    "kui", "kun", "kuo",
    "la", "lai", "lan", "lang", "lao", "le", "lei", "leng", "li", "lia", "lian", "liang", "liao", "lie", "lin", "ling",
    "liu", "long", "lou", "lu", "luan", "lue", "lun", "luo",
    "ma", "mai", "man", "mang", "mao", "me", "mei", "men", "meng", "mi", "mian", "miao", "mie", "min", "ming", "miu",
    "mo", "mou", "mu",
    "na", "nai", "nan", "nang", "nao", "ne", "nei", "nen", "neng", "ni", "nia", "nian", "niang", "niao", "nie", "nin",
    "ning", "niu", "nong", "nou", "nu", "nuan", "nue", "nuo",
    "o", "ou",
    "pa", "pai", "pan", "pang", "pao", "pei", "pen", "peng", "pi", "pian", "piao", "pie", "pin", "ping", "po", "pou", "pu",
    "qi", "qia", "qian", "qiang", "qiao", "qie", "qin", "qing", "qiong", "qiu", "qu", "quan", "que", "qun",
    "ran", "rang", "rao", "re", "ren", "reng", "ri", "rong", "rou", "ru", "rua", "ruan", "rui", "run", "ruo",
    "sa", "sai", "san", "sang", "sao", "se", "sen", "seng", "si", "song", "sou", "su", "suan", "sui", "sun", "suo",
    "ta", "tai", "tan", "tang", "tao", "te", "teng", "ti", "tian", "tiao", "tie", "ting", "tong", "tou", "tu", "tua",
    "tuan", "tui", "tun", "tuo",
    "wa", "wai", "wan", "wang", "wei", "wen", "weng", "wo", "wu",
    "xi", "xia", "xian", "xiang", "xiao", "xie", "xin", "xing", "xiong", "xiu", "xu", "xuan", "xue", "xun",
    "ya", "ya", "yan", "yang", "yao", "ye", "yi", "yia", "yian", "yiao", "yie", "yin", "ying", "yiu", "yo", "yong",
    "you", "yu", "yua", "yuan", "yue", "yun", "yuo",
    "za", "zai", "zan", "zang", "zao", "ze", "zei", "zen", "zeng", "zha", "zhai", "zhan", "zhang", "zhao", "zhe",
    "zhei", "zhen", "zheng", "zhi", "zhong", "zhou", "zhu", "zhua", "zhuai", "zhuan", "zhuang", "zhui", "zhun", "zhuo",
    "zi", "zong", "zou", "zu", "zuan", "zui", "zun", "zuo",
]


@dataclass
class EmailGenerationResult:
    """邮箱生成结果"""
    original: str
    synthetic: str
    username: str
    domain: str
    pattern: str


class EmailGenerator(BaseSyntheticGenerator):
    """邮箱地址生成器

    使用确定性算法生成逼真的邮箱地址，确保同一输入总是产生相同输出。

    Example:
        >>> gen = EmailGenerator()
        >>> result = gen.generate("zhangsan@example.com")
        >>> print(result.synthetic)
        lisi@163.com
    """

    # 邮箱格式正则
    EMAIL_PATTERN = re.compile(r"^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")

    def __init__(
        self,
        *,
        preserve_domain_type: bool = False,
        common_domains: list[str] | None = None,
        seed: int = 42,
    ):
        """初始化邮箱生成器

        Args:
            preserve_domain_type: 是否保持域名类型（国内/国外）
            common_domains: 自定义常用域名列表
            seed: 随机种子（用于确定性生成）
        """
        super().__init__(seed=seed)
        self.preserve_domain_type = preserve_domain_type
        self.common_domains = common_domains or COMMON_DOMAINS

        # 分类域名
        self.domestic_domains = [d for d in self.common_domains if
                                 d.endswith(".cn") or d in ["qq.com", "163.com", "126.com",
                                                              "sina.com", "sohu.com", "aliyun.com",
                                                              "foxmail.com", "139.com", "189.cn",
                                                              "yeah.net", "vip.qq.com"]]
        self.foreign_domains = [d for d in self.common_domains if d not in self.domestic_domains]

    def generate(self, original: str) -> EmailGenerationResult:
        """生成仿真邮箱地址

        Args:
            original: 原始邮箱地址

        Returns:
            EmailGenerationResult 包含生成的邮箱地址和元数据
        """
        # 验证和解析原邮箱
        match = self.EMAIL_PATTERN.match(original)
        if not match:
            return EmailGenerationResult(
                original=original,
                synthetic=original,
                username="",
                domain="",
                pattern="",
            )

        original_username = match.group(1)
        original_domain = match.group(2)
        original_pattern = self._detect_username_pattern(original_username)

        # 生成新用户名
        new_username = self._generate_username(original_username, original_pattern)

        # 生成新域名
        new_domain = self._generate_domain(original_domain)

        synthetic = f"{new_username}@{new_domain}"

        return EmailGenerationResult(
            original=original,
            synthetic=synthetic,
            username=new_username,
            domain=new_domain,
            pattern=original_pattern,
        )

    def _detect_username_pattern(self, username: str) -> str:
        """检测用户名格式模式"""
        has_dot = "." in username
        has_underscore = "_" in username
        has_digit = any(c.isdigit() for c in username)

        if has_dot and has_digit:
            return "mixed"
        elif has_dot:
            return "pinyin_dot"
        elif has_underscore:
            return "mixed"
        elif has_digit:
            return "pinyin_num"
        elif len(username) <= 3:
            return "initial"
        else:
            return "pinyin"

    def _generate_username(self, original: str, pattern: str) -> str:
        """生成新用户名"""
        hash_val = self._hash_string(original)

        if pattern == "pinyin":
            # 生成拼音全拼
            return self._generate_pinyin_username(hash_val, length=(6, 10))
        elif pattern == "pinyin_dot":
            # 生成带点的拼音
            return self._generate_pinyin_dot_username(hash_val)
        elif pattern == "pinyin_num":
            # 生成带数字的拼音
            return self._generate_pinyin_num_username(hash_val)
        elif pattern == "initial":
            # 生成首字母
            return self._generate_initial_username(hash_val)
        else:  # mixed
            # 生成混合格式
            return self._generate_mixed_username(hash_val)

    def _generate_pinyin_username(self, hash_val: int, length: tuple[int, int]) -> str:
        """生成拼音全拼用户名"""
        min_len, max_len = length
        syllable_count = (hash_val % (max_len - min_len + 1)) + min_len
        syllable_count = max(2, min(syllable_count, 10))  # 限制范围

        username = ""
        for i in range(syllable_count):
            h = (hash_val + i * 31) % (1 << 32)
            idx = h % len(PINYIN_SYLLABLES)
            username += PINYIN_SYLLABLES[idx]

        return username

    def _generate_pinyin_dot_username(self, hash_val: int) -> str:
        """生成带点的拼音用户名"""
        # 姓氏拼音 + 名字拼音
        h1 = hash_val % (1 << 32)
        h2 = (hash_val * 31 + 17) % (1 << 32)

        surname = PINYIN_SYLLABLES[h1 % 50]  # 前50个常见音节
        given = PINYIN_SYLLABLES[h2 % len(PINYIN_SYLLABLES)]

        return f"{surname}.{given}"

    def _generate_pinyin_num_username(self, hash_val: int) -> str:
        """生成带数字的拼音用户名"""
        base = self._generate_pinyin_username(hash_val, (4, 7))
        num = (hash_val % 9000) + 1000  # 1000-9999
        return f"{base}{num}"

    def _generate_initial_username(self, hash_val: int) -> str:
        """生成首字母用户名"""
        # 1-3个小写字母
        length = (hash_val % 3) + 1
        username = ""
        for i in range(length):
            h = (hash_val + i * 17) % (1 << 32)
            char = chr((h % 26) + ord('a'))
            username += char

        # 可能加数字
        if hash_val % 2 == 0:
            num = (hash_val % 100)
            username += str(num)

        return username

    def _generate_mixed_username(self, hash_val: int) -> str:
        """生成混合格式用户名"""
        # 基础拼音
        base = self._generate_pinyin_username(hash_val, (4, 6))

        # 可能加下划线或数字
        variant = hash_val % 3
        if variant == 0:
            num = (hash_val % 100)
            return f"{base}_{num}"
        elif variant == 1:
            num = (hash_val % 1000)
            return f"{base}{num}"
        else:
            return base

    def _generate_domain(self, original: str) -> str:
        """生成新域名"""
        hash_val = self._hash_string(original)

        if self.preserve_domain_type:
            # 判断是国内外域名
            is_domestic = original in self.domestic_domains or any(
                original.endswith(d) for d in self.domestic_domains if d != original
            )

            if is_domestic:
                candidates = self.domestic_domains
            else:
                candidates = self.foreign_domains
        else:
            candidates = self.common_domains

        idx = hash_val % len(candidates)
        return candidates[idx]

    def is_valid_email(self, email: str) -> bool:
        """检查是否是有效的邮箱地址"""
        return bool(self.EMAIL_PATTERN.match(email))
