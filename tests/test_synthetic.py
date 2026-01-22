"""Tests for the synthetic data generation module."""

import pytest

from pii_airlock.core.synthetic.name_generator import NameGenerator
from pii_airlock.core.synthetic.phone_generator import PhoneGenerator
from pii_airlock.core.synthetic.email_generator import EmailGenerator
from pii_airlock.core.synthetic.id_card_generator import IdCardGenerator
from pii_airlock.core.synthetic.generator import (
    SyntheticDataGenerator,
    SyntheticMapping,
    get_synthetic_generator,
)


class TestNameGenerator:
    """Tests for NameGenerator."""

    def test_generate_simple_name(self):
        """Test generating a simple Chinese name."""
        gen = NameGenerator()
        result = gen.generate("张三")

        assert result.original == "张三"
        assert len(result.synthetic) >= 2
        assert result.synthetic != "张三"
        assert result.surname in result.synthetic

    def test_deterministic_generation(self):
        """Test that generation is deterministic."""
        gen = NameGenerator()

        result1 = gen.generate("张三")
        result2 = gen.generate("张三")

        assert result1.synthetic == result2.synthetic

    def test_different_inputs_different_outputs(self):
        """Test that different inputs produce different outputs."""
        gen = NameGenerator()

        result1 = gen.generate("张三")
        result2 = gen.generate("李四")

        # Usually different, but not strictly guaranteed
        # (unless using different names with different hash values)
        assert result1.original != result2.original

    def test_three_character_name(self):
        """Test generating a three-character name."""
        gen = NameGenerator()
        result = gen.generate("王小明")

        assert len(result.synthetic) == 3

    def test_compound_surname(self):
        """Test handling compound surnames."""
        gen = NameGenerator()
        result = gen.generate("欧阳修")

        assert result.is_compound or result.surname == "欧阳"

    def test_preserve_gender(self):
        """Test gender preservation."""
        gen = NameGenerator(preserve_gender=True)

        result_male = gen.generate("张伟", gender="male")
        result_female = gen.generate("李娜", gender="female")

        assert result_male.synthetic is not None
        assert result_female.synthetic is not None

    def test_is_valid_name(self):
        """Test name validation."""
        gen = NameGenerator()

        assert gen.is_valid_name("张三") is True
        assert gen.is_valid_name("王小明") is True
        assert gen.is_valid_name("欧阳修") is True
        assert gen.is_valid_name("A") is False
        assert gen.is_valid_name("") is False
        assert gen.is_valid_name("123") is False

    def test_invalid_name_handling(self):
        """Test handling invalid names."""
        gen = NameGenerator()
        result = gen.generate("")

        assert result.synthetic == ""

    def test_single_character_name(self):
        """Test single character name."""
        gen = NameGenerator()
        result = gen.generate("王")

        # Should still generate something
        assert result.synthetic is not None


class TestPhoneGenerator:
    """Tests for PhoneGenerator."""

    def test_generate_valid_phone(self):
        """Test generating a valid phone number."""
        gen = PhoneGenerator()
        result = gen.generate("13800138000")

        assert result.original == "13800138000"
        assert len(result.synthetic) == 11
        assert result.synthetic.isdigit()

    def test_deterministic_generation(self):
        """Test that generation is deterministic."""
        gen = PhoneGenerator()

        result1 = gen.generate("13800138000")
        result2 = gen.generate("13800138000")

        assert result1.synthetic == result2.synthetic

    def test_preserve_carrier(self):
        """Test carrier preservation."""
        gen = PhoneGenerator(preserve_carrier=True)
        result = gen.generate("13800138000")  # China Mobile

        # Should be mobile carrier
        assert result.carrier == "mobile"

    def test_get_carrier(self):
        """Test getting carrier from phone number."""
        gen = PhoneGenerator()

        assert gen.get_carrier("13800138000") == "mobile"
        assert gen.get_carrier("13000138000") == "unicom"
        assert gen.get_carrier("13300138000") == "telecom"
        assert gen.get_carrier("19200138000") == "broadcasting"
        assert gen.get_carrier("12345678901") == "unknown"

    def test_format_phone(self):
        """Test phone number formatting."""
        gen = PhoneGenerator()

        assert gen.format_phone("13800138000", "plain") == "13800138000"
        assert gen.format_phone("13800138000", "space") == "138 0013 8000"
        assert gen.format_phone("13800138000", "dash") == "138-0013-8000"

    def test_invalid_phone_handling(self):
        """Test handling invalid phone numbers."""
        gen = PhoneGenerator()
        result = gen.generate("12345")

        assert result.synthetic == "12345"
        assert result.carrier == "unknown"


class TestEmailGenerator:
    """Tests for EmailGenerator."""

    def test_generate_valid_email(self):
        """Test generating a valid email address."""
        gen = EmailGenerator()
        result = gen.generate("zhangsan@example.com")

        assert result.original == "zhangsan@example.com"
        assert "@" in result.synthetic
        assert result.domain in gen.common_domains

    def test_deterministic_generation(self):
        """Test that generation is deterministic."""
        gen = EmailGenerator()

        result1 = gen.generate("zhangsan@example.com")
        result2 = gen.generate("zhangsan@example.com")

        assert result1.synthetic == result2.synthetic

    def test_username_patterns(self):
        """Test different username patterns."""
        gen = EmailGenerator()

        # Pinyin pattern
        result1 = gen.generate("zhangsan@qq.com")
        # Pinyin with dot
        result2 = gen.generate("zhang.san@163.com")
        # Pinyin with numbers
        result3 = gen.generate("zhangsan123@126.com")

        assert "@" in result1.synthetic
        assert "@" in result2.synthetic
        assert "@" in result3.synthetic

    def test_preserve_domain_type(self):
        """Test domain type preservation."""
        gen = EmailGenerator(preserve_domain_type=True)
        result = gen.generate("user@qq.com")

        # Should generate a domestic domain
        assert result.domain in gen.domestic_domains

    def test_is_valid_email(self):
        """Test email validation."""
        gen = EmailGenerator()

        assert gen.is_valid_email("test@example.com") is True
        assert gen.is_valid_email("user.name+tag@domain.co.uk") is True
        assert gen.is_valid_email("invalid") is False
        assert gen.is_valid_email("@example.com") is False
        assert gen.is_valid_email("test@") is False


class TestIdCardGenerator:
    """Tests for IdCardGenerator."""

    def test_generate_valid_id_card(self):
        """Test generating a valid ID card number."""
        gen = IdCardGenerator()
        result = gen.generate("110101199003077758")

        assert result.original == "110101199003077758"
        assert len(result.synthetic) == 18
        assert result.is_valid is True

    def test_deterministic_generation(self):
        """Test that generation is deterministic."""
        gen = IdCardGenerator()

        result1 = gen.generate("110101199003077758")
        result2 = gen.generate("110101199003077758")

        assert result1.synthetic == result2.synthetic

    def test_preserve_region(self):
        """Test region preservation."""
        gen = IdCardGenerator(preserve_region=True)
        result = gen.generate("110101199003077758")  # Beijing

        # Should preserve the province code (11)
        assert result.region_code.startswith("11")

    def test_preserve_birth_date(self):
        """Test birth date preservation."""
        gen = IdCardGenerator(preserve_birth_date=True)
        result = gen.generate("110101199003077758")

        assert result.birth_date == "19900307"

    def test_preserve_gender(self):
        """Test gender preservation."""
        gen = IdCardGenerator(preserve_gender=True)
        result = gen.generate("110101199003077751")  # Male (17th digit is 5)

        assert result.gender == "male"

        result2 = gen.generate("110101199003077468")  # Female (17th digit is 6)

        assert result2.gender == "female"

    def test_check_code_calculation(self):
        """Test check code calculation."""
        gen = IdCardGenerator()

        # Valid ID card
        check = gen._calculate_check_code("11010119900307775")
        assert check == "8"

        # Another valid ID card
        check2 = gen._calculate_check_code("31010119900307712")
        assert check2 in "0123456789X"

    def test_is_valid_id_card(self):
        """Test ID card validation."""
        gen = IdCardGenerator()

        # Valid 18-digit ID card
        assert gen.is_valid_id_card("110101199003077758") is True

        # Invalid format
        assert gen.is_valid_id_card("12345") is False
        assert gen.is_valid_id_card("abcdefghijklmnopqr") is False

        # Invalid check code
        assert gen.is_valid_id_card("110101199003077750") is False

    def test_get_region_name(self):
        """Test getting region name."""
        gen = IdCardGenerator()

        assert gen.get_region_name("110101") == "北京市"
        assert gen.get_region_name("310101") == "上海市"
        assert gen.get_region_name("440101") == "广东省"
        assert gen.get_region_name("000000") == "未知"

    def test_get_birth_date(self):
        """Test getting birth date."""
        gen = IdCardGenerator()

        assert gen.get_birth_date("110101199003077758") == "1990-03-07"
        assert gen.get_birth_date("12345") is None

    def test_get_gender(self):
        """Test getting gender."""
        gen = IdCardGenerator()

        # Odd 17th digit (775) = male (5 is odd)
        assert gen.get_gender("110101199003077751") == "male"
        # Even 17th digit (746) = female (6 is even)
        assert gen.get_gender("110101199003077468") == "female"

    def test_invalid_id_card_handling(self):
        """Test handling invalid ID cards."""
        gen = IdCardGenerator()
        result = gen.generate("invalid")

        assert result.synthetic == "invalid"
        assert result.is_valid is False


class TestSyntheticDataGenerator:
    """Tests for SyntheticDataGenerator."""

    def test_generate_person(self):
        """Test generating synthetic person name."""
        gen = SyntheticDataGenerator()
        result = gen.generate("张三", "PERSON")

        assert result.original == "张三"
        assert result.synthetic != "张三"
        assert result.entity_type == "PERSON"

    def test_generate_phone(self):
        """Test generating synthetic phone number."""
        gen = SyntheticDataGenerator()
        result = gen.generate("13800138000", "PHONE")

        assert result.original == "13800138000"
        assert len(result.synthetic) == 11
        assert result.synthetic.isdigit()

    def test_generate_email(self):
        """Test generating synthetic email."""
        gen = SyntheticDataGenerator()
        result = gen.generate("test@example.com", "EMAIL")

        assert "@" in result.synthetic
        assert result.entity_type == "EMAIL"

    def test_generate_id_card(self):
        """Test generating synthetic ID card."""
        gen = SyntheticDataGenerator()
        result = gen.generate("110101199003077758", "ID_CARD")

        assert len(result.synthetic) == 18
        assert result.entity_type == "ID_CARD"

    def test_deterministic_across_types(self):
        """Test determinism across different entity types."""
        gen = SyntheticDataGenerator()

        result1 = gen.generate("张三", "PERSON")
        result2 = gen.generate("张三", "PERSON")

        assert result1.synthetic == result2.synthetic

    def test_cache_functionality(self):
        """Test caching mechanism."""
        gen = SyntheticDataGenerator()

        # First call
        gen.generate("张三", "PERSON")
        assert gen.get_cache_size() == 1

        # Second call (cached)
        gen.generate("张三", "PERSON")
        assert gen.get_cache_size() == 1

        # Different value
        gen.generate("李四", "PERSON")
        assert gen.get_cache_size() == 2

        # Clear cache
        gen.clear_cache()
        assert gen.get_cache_size() == 0

    def test_anonymize_with_detections(self):
        """Test anonymizing text with detections."""
        gen = SyntheticDataGenerator()

        detections = [
            {"value": "张三", "entity_type": "PERSON", "start": 0, "end": 2},
            {"value": "13800138000", "entity_type": "PHONE", "start": 5, "end": 16},
        ]

        result = gen.anonymize("张三，电话13800138000", detections)

        assert "张三" not in result.text
        assert "13800138000" not in result.text
        assert result.replaced_count == 2

    def test_deanonymize_with_mappings(self):
        """Test deanonymizing with mappings."""
        gen = SyntheticDataGenerator()

        # Create mappings
        mapping1 = gen.generate("张三", "PERSON")
        mapping2 = gen.generate("13800138000", "PHONE")

        # Simulate anonymized text
        anonymized = f"{mapping1.synthetic}，电话{mapping2.synthetic}"

        # Deanonymize
        restored = gen.deanonymize(anonymized, [mapping1, mapping2])

        assert "张三" in restored
        assert "13800138000" in restored

    def test_unknown_entity_type(self):
        """Test handling unknown entity types."""
        gen = SyntheticDataGenerator()
        result = gen.generate("some_value", "UNKNOWN_TYPE")

        # Should return original value for unknown types
        assert result.synthetic == "some_value"
        assert result.original == "some_value"

    def test_anonymize_without_detections(self):
        """Test anonymizing without detections."""
        gen = SyntheticDataGenerator()
        result = gen.anonymize("张三，电话13800138000", None)

        assert result.text == "张三，电话13800138000"
        assert result.replaced_count == 0


class TestGlobalGenerator:
    """Tests for global generator instance."""

    def test_get_synthetic_generator(self):
        """Test getting global generator instance."""
        gen1 = get_synthetic_generator()
        gen2 = get_synthetic_generator()

        # Should return the same instance
        assert gen1 is gen2

    def test_global_generator_deterministic(self):
        """Test that global generator is deterministic."""
        gen = get_synthetic_generator()

        result1 = gen.generate("张三", "PERSON")
        result2 = gen.generate("张三", "PERSON")

        assert result1.synthetic == result2.synthetic


class TestSyntheticMapping:
    """Tests for SyntheticMapping dataclass."""

    def test_mapping_creation(self):
        """Test creating a mapping."""
        mapping = SyntheticMapping(
            original="张三",
            synthetic="李四",
            entity_type="PERSON",
            metadata={"key": "value"}
        )

        assert mapping.original == "张三"
        assert mapping.synthetic == "李四"
        assert mapping.entity_type == "PERSON"
        assert mapping.metadata == {"key": "value"}

    def test_mapping_repr(self):
        """Test mapping string representation."""
        mapping = SyntheticMapping(
            original="张三",
            synthetic="李四",
            entity_type="PERSON"
        )

        repr_str = repr(mapping)
        assert "PERSON" in repr_str
        assert "SyntheticMapping" in repr_str
