import pytest
from pydantic import ValidationError

from app.schemas import Token, Hwid, TokenData


class TestToken:
    def test_token_creation_valid(self):
        token = Token(access_token="test-token-123", token_type="bearer")
        
        assert token.access_token == "test-token-123"
        assert token.token_type == "bearer"

    def test_token_creation_with_different_token_type(self):
        token = Token(access_token="test-token-123", token_type="custom")
        
        assert token.access_token == "test-token-123"
        assert token.token_type == "custom"

    def test_token_creation_empty_strings(self):
        token = Token(access_token="", token_type="")
        
        assert token.access_token == ""
        assert token.token_type == ""

    def test_token_missing_access_token(self):
        with pytest.raises(ValidationError) as exc_info:
            Token(token_type="bearer")
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("access_token",)
        assert errors[0]["type"] == "missing"

    def test_token_missing_token_type(self):
        with pytest.raises(ValidationError) as exc_info:
            Token(access_token="test-token-123")
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("token_type",)
        assert errors[0]["type"] == "missing"

    def test_token_json_serialization(self):
        token = Token(access_token="test-token-123", token_type="bearer")
        json_data = token.model_dump()
        
        assert json_data == {
            "access_token": "test-token-123",
            "token_type": "bearer"
        }

    def test_token_from_dict(self):
        data = {"access_token": "test-token-123", "token_type": "bearer"}
        token = Token(**data)
        
        assert token.access_token == "test-token-123"
        assert token.token_type == "bearer"

    def test_token_extra_fields_ignored(self):
        # Pydantic should ignore extra fields by default
        data = {
            "access_token": "test-token-123", 
            "token_type": "bearer",
            "extra_field": "should_be_ignored"
        }
        token = Token(**data)
        
        assert token.access_token == "test-token-123"
        assert token.token_type == "bearer"
        assert not hasattr(token, "extra_field")


class TestHwid:
    def test_hwid_creation_valid(self):
        hwid = Hwid(value="test-hwid-12345")
        
        assert hwid.value == "test-hwid-12345"

    def test_hwid_creation_empty_string(self):
        hwid = Hwid(value="")
        
        assert hwid.value == ""

    def test_hwid_creation_long_value(self):
        long_value = "a" * 1000
        hwid = Hwid(value=long_value)
        
        assert hwid.value == long_value

    def test_hwid_creation_special_characters(self):
        special_value = "hwid-123_!@#$%^&*()+={}[]|\\:;\"'<>,.?/"
        hwid = Hwid(value=special_value)
        
        assert hwid.value == special_value

    def test_hwid_missing_value(self):
        with pytest.raises(ValidationError) as exc_info:
            Hwid()
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("value",)
        assert errors[0]["type"] == "missing"

    def test_hwid_json_serialization(self):
        hwid = Hwid(value="test-hwid-12345")
        json_data = hwid.model_dump()
        
        assert json_data == {"value": "test-hwid-12345"}

    def test_hwid_from_dict(self):
        data = {"value": "test-hwid-12345"}
        hwid = Hwid(**data)
        
        assert hwid.value == "test-hwid-12345"

    def test_hwid_numeric_string(self):
        hwid = Hwid(value="123456789")
        
        assert hwid.value == "123456789"
        assert isinstance(hwid.value, str)

    def test_hwid_whitespace_value(self):
        hwid = Hwid(value="   test-hwid   ")
        
        assert hwid.value == "   test-hwid   "  # Should preserve whitespace


class TestTokenData:
    def test_token_data_creation_all_fields(self):
        token_data = TokenData(
            telegram_id="123456789",
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        
        assert token_data.telegram_id == "123456789"
        assert token_data.username == "testuser"
        assert token_data.is_banned is False
        assert token_data.hwid == "test-hwid-123"

    def test_token_data_creation_minimal_required(self):
        token_data = TokenData(
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        
        assert token_data.telegram_id is None  # Default value
        assert token_data.username == "testuser"
        assert token_data.is_banned is False
        assert token_data.hwid == "test-hwid-123"

    def test_token_data_telegram_id_none(self):
        token_data = TokenData(
            telegram_id=None,
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        
        assert token_data.telegram_id is None
        assert token_data.username == "testuser"

    def test_token_data_banned_user(self):
        token_data = TokenData(
            telegram_id="123456789",
            username="banneduser",
            is_banned=True,
            hwid="test-hwid-123"
        )
        
        assert token_data.is_banned is True

    def test_token_data_missing_username(self):
        with pytest.raises(ValidationError) as exc_info:
            TokenData(
                telegram_id="123456789",
                is_banned=False,
                hwid="test-hwid-123"
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("username",)
        assert errors[0]["type"] == "missing"

    def test_token_data_missing_is_banned(self):
        with pytest.raises(ValidationError) as exc_info:
            TokenData(
                telegram_id="123456789",
                username="testuser",
                hwid="test-hwid-123"
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("is_banned",)
        assert errors[0]["type"] == "missing"

    def test_token_data_missing_hwid(self):
        with pytest.raises(ValidationError) as exc_info:
            TokenData(
                telegram_id="123456789",
                username="testuser",
                is_banned=False
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("hwid",)
        assert errors[0]["type"] == "missing"

    def test_token_data_json_serialization(self):
        token_data = TokenData(
            telegram_id="123456789",
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        json_data = token_data.model_dump()
        
        expected = {
            "telegram_id": "123456789",
            "username": "testuser",
            "is_banned": False,
            "hwid": "test-hwid-123"
        }
        assert json_data == expected

    def test_token_data_json_serialization_with_none(self):
        token_data = TokenData(
            telegram_id=None,
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        json_data = token_data.model_dump()
        
        expected = {
            "telegram_id": None,
            "username": "testuser",
            "is_banned": False,
            "hwid": "test-hwid-123"
        }
        assert json_data == expected

    def test_token_data_from_dict(self):
        data = {
            "telegram_id": "123456789",
            "username": "testuser",
            "is_banned": False,
            "hwid": "test-hwid-123"
        }
        token_data = TokenData(**data)
        
        assert token_data.telegram_id == "123456789"
        assert token_data.username == "testuser"
        assert token_data.is_banned is False
        assert token_data.hwid == "test-hwid-123"

    def test_token_data_empty_strings(self):
        token_data = TokenData(
            telegram_id="",
            username="",
            is_banned=False,
            hwid=""
        )
        
        assert token_data.telegram_id == ""
        assert token_data.username == ""
        assert token_data.hwid == ""

    def test_token_data_field_types(self):
        token_data = TokenData(
            telegram_id="123456789",
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        
        assert isinstance(token_data.telegram_id, str)
        assert isinstance(token_data.username, str)
        assert isinstance(token_data.is_banned, bool)
        assert isinstance(token_data.hwid, str)

    def test_token_data_boolean_coercion(self):
        # Test that various values are properly coerced to boolean
        token_data = TokenData(
            username="testuser",
            is_banned=1,  # Should be coerced to True
            hwid="test-hwid-123"
        )
        
        assert token_data.is_banned is True

    def test_token_data_default_telegram_id(self):
        # Test that telegram_id defaults to None when not provided
        token_data = TokenData(
            username="testuser",
            is_banned=False,
            hwid="test-hwid-123"
        )
        
        assert token_data.telegram_id is None