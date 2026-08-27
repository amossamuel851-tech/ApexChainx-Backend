import unittest

from app.core.config import Settings, validate_critical_settings

# Valid Fernet key (32 url-safe base64 bytes) for WEBHOOK_SECRET_ENCRYPTION_KEY
VALID_FERNET_KEY = "3Axxvzn-yND3zGIIHvm5ygVFcgarKcvyczwe8lga-7A="


class ConfigValidationTests(unittest.TestCase):
    def make_settings(self, **overrides):
        defaults = {
            "PROJECT_NAME": "ApexChainx API",
            "VERSION": "1.0.0",
            "DEBUG": False,
            "DATABASE_URL": "postgresql://postgres:password@localhost:5432/apexchainx",
            "API_V1_PREFIX": "/api/v1",
            "ALLOWED_ORIGINS": ["http://localhost:3000"],
            "CELERY_BROKER_URL": "redis://localhost:6379/0",
            "CELERY_RESULT_BACKEND": "redis://localhost:6379/0",
            "CELERY_TASK_ALWAYS_EAGER": True,
            "SLA_CONTRACT_ADDRESS": "local-sla-calculator",
            "STELLAR_NETWORK": "testnet",
            "CONTRACT_EXECUTION_MODE": "local_adapter",
            "ENVIRONMENT": "local",
            "SECRET_KEY": "apexchainx-dev-secret",
            "PAYMENT_WEBHOOK_SECRET": "test-webhook-secret-1234",
            "WEBHOOK_SECRET_ENCRYPTION_KEY": VALID_FERNET_KEY,
        }
        defaults.update(overrides)
        return Settings.model_construct(**defaults)

    def test_valid_settings_pass(self):
        validate_critical_settings(self.make_settings())

    def test_invalid_api_prefix_fails_fast(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(self.make_settings(API_V1_PREFIX="api/v1"))

        self.assertIn("API_V1_PREFIX must start with '/'", str(ctx.exception))

    def test_invalid_origins_fail_fast(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(self.make_settings(ALLOWED_ORIGINS=["localhost:3000"]))

        self.assertIn("ALLOWED_ORIGINS must contain valid http or https origins", str(ctx.exception))

    def test_invalid_contract_execution_mode_fails_fast(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(self.make_settings(CONTRACT_EXECUTION_MODE="unsupported"))

        self.assertIn("CONTRACT_EXECUTION_MODE must be one of", str(ctx.exception))

    def test_non_eager_celery_requires_broker_and_backend(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    CELERY_TASK_ALWAYS_EAGER=False,
                    CELERY_BROKER_URL="",
                    CELERY_RESULT_BACKEND="",
                )
            )

        message = str(ctx.exception)
        self.assertIn("CELERY_BROKER_URL must not be empty", message)
        self.assertIn("CELERY_RESULT_BACKEND must not be empty", message)

    def test_webhook_dispatch_limits_must_be_positive(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    WEBHOOK_MAX_CONCURRENT_DISPATCHES=0,
                    WEBHOOK_MAX_CONCURRENT_DISPATCHES_PER_WEBHOOK=-1,
                )
            )

        message = str(ctx.exception)
        self.assertIn("WEBHOOK_MAX_CONCURRENT_DISPATCHES must be > 0", message)
        self.assertIn("WEBHOOK_MAX_CONCURRENT_DISPATCHES_PER_WEBHOOK must be > 0", message)

    def test_default_secret_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(ENVIRONMENT="production", SECRET_KEY="apexchainx-dev-secret")
            )

        self.assertIn("SECRET_KEY must be set to a secure", str(ctx.exception))

    def test_default_secret_key_accepted_in_local(self):
        validate_critical_settings(
            self.make_settings(ENVIRONMENT="local", SECRET_KEY="apexchainx-dev-secret")
        )

    def test_default_secret_key_accepted_in_test(self):
        validate_critical_settings(
            self.make_settings(ENVIRONMENT="test", SECRET_KEY="apexchainx-dev-secret")
        )

    def test_custom_secret_key_accepted_in_production(self):
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="production",
                SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
            )
        )

    def test_empty_secret_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(self.make_settings(ENVIRONMENT="production", SECRET_KEY=""))

        self.assertIn("SECRET_KEY must be set to a secure", str(ctx.exception))

    def test_short_secret_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(self.make_settings(ENVIRONMENT="production", SECRET_KEY="short"))

        self.assertIn("SECRET_KEY must be set to a secure", str(ctx.exception))

    # ------------------------------------------------------------------ #
    # Whitespace-only SECRET_KEY                                          #
    # ------------------------------------------------------------------ #

    def test_whitespace_only_secret_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(ENVIRONMENT="production", SECRET_KEY="   ")
            )

        self.assertIn("SECRET_KEY must be set to a secure", str(ctx.exception))

    # ------------------------------------------------------------------ #
    # Staging environment (non-local, non-test, non-production)           #
    # ------------------------------------------------------------------ #

    def test_default_secret_key_rejected_in_staging(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(ENVIRONMENT="staging", SECRET_KEY="apexchainx-dev-secret")
            )

        self.assertIn("SECRET_KEY must be set to a secure", str(ctx.exception))

    def test_custom_secret_key_accepted_in_staging(self):
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="staging",
                SECRET_KEY="a-very-long-secure-staging-secret-key-abcdefgh",
            )
        )

    # ------------------------------------------------------------------ #
    # Error message includes environment name                              #
    # ------------------------------------------------------------------ #

    def test_secret_key_error_includes_environment_name(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(ENVIRONMENT="production", SECRET_KEY="short")
            )

        self.assertIn("ENVIRONMENT='production'", str(ctx.exception))

    # ------------------------------------------------------------------ #
    # IMPERSONATION_SIGNING_KEY validation                                #
    # ------------------------------------------------------------------ #

    def test_short_impersonation_signing_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
                    IMPERSONATION_SIGNING_KEY="short",
                )
            )

        self.assertIn("IMPERSONATION_SIGNING_KEY", str(ctx.exception))

    def test_empty_impersonation_signing_key_accepted_in_production(self):
        # Empty IMPERSONATION_SIGNING_KEY is fine — it falls back to SECRET_KEY
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="production",
                SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
                IMPERSONATION_SIGNING_KEY="",
            )
        )

    def test_valid_impersonation_signing_key_accepted_in_production(self):
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="production",
                SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
                IMPERSONATION_SIGNING_KEY="a-different-long-secure-key-for-impersonation-xx",
            )
        )

    def test_impersonation_key_not_checked_in_local(self):
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="local",
                SECRET_KEY="apexchainx-dev-secret",
                IMPERSONATION_SIGNING_KEY="short",
            )
        )

    # ------------------------------------------------------------------ #
    # PAYMENT_WEBHOOK_SECRET validation in production                     #
    # ------------------------------------------------------------------ #

    def test_empty_webhook_secret_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
                    PAYMENT_WEBHOOK_SECRET="",
                )
            )

        self.assertIn("PAYMENT_WEBHOOK_SECRET", str(ctx.exception))

    def test_webhook_secret_not_checked_in_local(self):
        validate_critical_settings(
            self.make_settings(ENVIRONMENT="local", PAYMENT_WEBHOOK_SECRET="")
        )

    # ------------------------------------------------------------------ #
    # WEBHOOK_SECRET_ENCRYPTION_KEY validation (#266)                     #
    # ------------------------------------------------------------------ #

    def test_empty_webhook_secret_encryption_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
                    WEBHOOK_SECRET_ENCRYPTION_KEY="",
                )
            )

        self.assertIn("WEBHOOK_SECRET_ENCRYPTION_KEY", str(ctx.exception))

    def test_invalid_fernet_key_rejected_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
                    WEBHOOK_SECRET_ENCRYPTION_KEY="not-a-fernet-key",
                )
            )

        self.assertIn("WEBHOOK_SECRET_ENCRYPTION_KEY", str(ctx.exception))

    def test_valid_fernet_key_accepted_in_production(self):
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="production",
                SECRET_KEY="a-very-long-secure-production-secret-key-1234567890",
            )
        )

    def test_webhook_secret_encryption_key_not_required_in_local(self):
        validate_critical_settings(
            self.make_settings(ENVIRONMENT="local", WEBHOOK_SECRET_ENCRYPTION_KEY="")
        )

    # ------------------------------------------------------------------ #
    # Minimum length constant                                             #
    # ------------------------------------------------------------------ #

    def test_min_secret_key_length_is_32(self):
        from app.core.config import MIN_SECRET_KEY_LENGTH

        self.assertEqual(MIN_SECRET_KEY_LENGTH, 32)

    def test_exactly_31_char_key_rejected_in_production(self):
        with self.assertRaises(ValueError):
            validate_critical_settings(
                self.make_settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="a" * 31,
                )
            )

    def test_exactly_32_char_key_accepted_in_production(self):
        validate_critical_settings(
            self.make_settings(
                ENVIRONMENT="production",
                SECRET_KEY="a" * 32,
            )
        )

    # ------------------------------------------------------------------ #
    # Multiple validation errors collected                                 #
    # ------------------------------------------------------------------ #

    def test_multiple_secret_key_errors_in_production(self):
        with self.assertRaises(ValueError) as ctx:
            validate_critical_settings(
                self.make_settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="",
                    PAYMENT_WEBHOOK_SECRET="",
                )
            )

        message = str(ctx.exception)
        self.assertIn("SECRET_KEY must be set to a secure", message)
        self.assertIn("PAYMENT_WEBHOOK_SECRET", message)


if __name__ == "__main__":
    unittest.main()
