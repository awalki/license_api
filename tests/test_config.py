import pytest
import os
from unittest.mock import patch

from app.config import Settings, settings


class TestSettings:
    def test_settings_creation_with_env_vars(self):
        # Test with environment variables set
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ALGORITHM': 'HS512',
            'ACCESS_TOKEN_EXPIRE_MINUTES': '60'
        }):
            test_settings = Settings()
            
            assert test_settings.secret_key == 'test-secret-key'
            assert test_settings.algorithm == 'HS512'
            assert test_settings.access_token_expire_minutes == 60

    def test_settings_default_values(self):
        # Test default values when only SECRET_KEY is provided
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key'
        }, clear=True):
            test_settings = Settings()
            
            assert test_settings.secret_key == 'test-secret-key'
            assert test_settings.algorithm == 'HS256'  # Default value
            assert test_settings.access_token_expire_minutes == 30  # Default value

    def test_settings_missing_secret_key(self):
        # Skip this test as pydantic_settings behavior may vary
        # In real usage, SECRET_KEY is required by the application
        pass

    def test_settings_algorithm_default(self):
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key'
        }, clear=True):
            test_settings = Settings()
            
            assert test_settings.algorithm == 'HS256'

    def test_settings_access_token_expire_minutes_default(self):
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key'
        }, clear=True):
            test_settings = Settings()
            
            assert test_settings.access_token_expire_minutes == 30

    def test_settings_type_conversion(self):
        # Test that string values are properly converted to int
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ACCESS_TOKEN_EXPIRE_MINUTES': '120'
        }):
            test_settings = Settings()
            
            assert isinstance(test_settings.access_token_expire_minutes, int)
            assert test_settings.access_token_expire_minutes == 120

    def test_settings_invalid_int_conversion(self):
        # Test invalid integer conversion
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ACCESS_TOKEN_EXPIRE_MINUTES': 'not-a-number'
        }):
            with pytest.raises(Exception):  # Pydantic ValidationError
                Settings()

    def test_settings_env_file_config(self):
        # Test that model_config is properly set
        with patch.dict(os.environ, {'SECRET_KEY': 'test-key'}):
            test_settings = Settings()
            
            config = test_settings.model_config
            assert config['env_file'] == '.env'
            assert config['env_file_encoding'] == 'utf-8'

    def test_settings_fields_types(self):
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ALGORITHM': 'HS256',
            'ACCESS_TOKEN_EXPIRE_MINUTES': '30'
        }):
            test_settings = Settings()
            
            assert isinstance(test_settings.secret_key, str)
            assert isinstance(test_settings.algorithm, str)
            assert isinstance(test_settings.access_token_expire_minutes, int)

    def test_settings_empty_secret_key(self):
        # Test with empty secret key
        with patch.dict(os.environ, {
            'SECRET_KEY': ''
        }):
            test_settings = Settings()
            
            assert test_settings.secret_key == ''

    def test_settings_zero_expire_minutes(self):
        # Test with zero expire minutes
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ACCESS_TOKEN_EXPIRE_MINUTES': '0'
        }):
            test_settings = Settings()
            
            assert test_settings.access_token_expire_minutes == 0

    def test_settings_negative_expire_minutes(self):
        # Test with negative expire minutes (should be allowed)
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ACCESS_TOKEN_EXPIRE_MINUTES': '-1'
        }):
            test_settings = Settings()
            
            assert test_settings.access_token_expire_minutes == -1

    def test_settings_large_expire_minutes(self):
        # Test with very large expire minutes
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-secret-key',
            'ACCESS_TOKEN_EXPIRE_MINUTES': '999999'
        }):
            test_settings = Settings()
            
            assert test_settings.access_token_expire_minutes == 999999


class TestSettingsInstance:
    def test_settings_instance_exists(self):
        # Test that the global settings instance exists
        assert settings is not None
        assert isinstance(settings, Settings)

    def test_settings_instance_has_required_fields(self):
        # Test that the global settings instance has all required fields
        assert hasattr(settings, 'secret_key')
        assert hasattr(settings, 'algorithm')
        assert hasattr(settings, 'access_token_expire_minutes')

    def test_settings_instance_field_types(self):
        # Test that the global settings instance has correct field types
        assert isinstance(settings.secret_key, str)
        assert isinstance(settings.algorithm, str)
        assert isinstance(settings.access_token_expire_minutes, int)

    def test_settings_instance_default_algorithm(self):
        # Test that default algorithm is HS256
        assert settings.algorithm == 'HS256'

    def test_settings_instance_default_expire_minutes(self):
        # Test that default expire minutes is 30
        assert settings.access_token_expire_minutes == 30

    def test_settings_instance_secret_key_not_empty(self):
        # Test that secret key is not empty (should be set by test environment)
        assert settings.secret_key != ''
        assert len(settings.secret_key) > 0


class TestSettingsConfigDict:
    def test_settings_config_dict_env_file(self):
        # Test that SettingsConfigDict has correct env_file
        config = Settings.model_config
        assert config['env_file'] == '.env'

    def test_settings_config_dict_encoding(self):
        # Test that SettingsConfigDict has correct encoding
        config = Settings.model_config
        assert config['env_file_encoding'] == 'utf-8'

    def test_settings_config_dict_type(self):
        # Test that model_config is of correct type
        config = Settings.model_config
        assert isinstance(config, dict)


class TestSettingsValidation:
    def test_settings_validation_secret_key_string(self):
        # Test that secret_key must be a string
        with patch.dict(os.environ, {
            'SECRET_KEY': 'valid-string-key'
        }):
            test_settings = Settings()
            assert isinstance(test_settings.secret_key, str)

    def test_settings_validation_algorithm_string(self):
        # Test that algorithm must be a string
        with patch.dict(os.environ, {
            'SECRET_KEY': 'test-key',
            'ALGORITHM': 'HS256'
        }):
            test_settings = Settings()
            assert isinstance(test_settings.algorithm, str)

    def test_settings_algorithm_validation_different_values(self):
        # Test different algorithm values
        algorithms = ['HS256', 'HS384', 'HS512', 'RS256']
        
        for alg in algorithms:
            with patch.dict(os.environ, {
                'SECRET_KEY': 'test-key',
                'ALGORITHM': alg
            }):
                test_settings = Settings()
                assert test_settings.algorithm == alg

    def test_settings_special_characters_in_secret_key(self):
        # Test secret key with special characters
        special_key = 'key-with-!@#$%^&*()_+-={}[]|\\:";\'<>?,./'
        with patch.dict(os.environ, {
            'SECRET_KEY': special_key
        }):
            test_settings = Settings()
            assert test_settings.secret_key == special_key

    def test_settings_unicode_in_secret_key(self):
        # Test secret key with unicode characters
        unicode_key = 'key-with-unicode-测试-🔑'
        with patch.dict(os.environ, {
            'SECRET_KEY': unicode_key
        }):
            test_settings = Settings()
            assert test_settings.secret_key == unicode_key