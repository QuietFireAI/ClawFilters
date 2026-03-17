# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_middleware_depth.py
# REM: Coverage depth tests for core/middleware.py
# REM: Pure unit tests for RateLimiter, CircuitBreaker, get_circuit
# REM: Middleware dispatch tests use the FastAPI test client (no external deps needed)

import time
import pytest

from core.middleware import (
    RateLimiter, CircuitBreaker, CircuitState, CircuitOpenError,
    get_circuit, circuit_protected,
)


# ═══════════════════════════════════════════════════════════════════════════════
# CircuitState enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestCircuitStateEnum:
    def test_closed(self):
        assert CircuitState.CLOSED == "closed"

    def test_open(self):
        assert CircuitState.OPEN == "open"

    def test_half_open(self):
        assert CircuitState.HALF_OPEN == "half_open"


# ═══════════════════════════════════════════════════════════════════════════════
# RateLimiter
# ═══════════════════════════════════════════════════════════════════════════════

class TestRateLimiter:
    def test_init_defaults(self):
        rl = RateLimiter()
        assert rl.requests_per_minute == 60
        assert rl.burst_size == 10

    def test_init_custom(self):
        rl = RateLimiter(requests_per_minute=30, burst_size=5)
        assert rl.requests_per_minute == 30
        assert rl.burst_size == 5

    def test_tokens_per_second(self):
        rl = RateLimiter(requests_per_minute=60)
        assert rl.tokens_per_second == 1.0

    def test_refill_bucket_fills_to_burst(self):
        rl = RateLimiter(requests_per_minute=600, burst_size=10)
        bucket = {"tokens": 0, "last_update": time.time() - 60}
        rl._refill_bucket(bucket)
        assert bucket["tokens"] == 10  # capped at burst_size

    def test_refill_bucket_partial(self):
        rl = RateLimiter(requests_per_minute=60, burst_size=100)
        bucket = {"tokens": 0, "last_update": time.time() - 1}
        rl._refill_bucket(bucket)
        # 1 second * 1 token/sec = 1 token
        assert bucket["tokens"] >= 0.9

    def test_cleanup_stale_buckets_skips_if_recent(self):
        rl = RateLimiter()
        rl._last_cleanup = time.time()  # just cleaned up
        # Should not raise
        rl._cleanup_stale_buckets()

    def test_cleanup_removes_stale(self):
        rl = RateLimiter()
        rl._last_cleanup = time.time() - 120  # expired
        # Add a stale bucket
        rl._buckets["ip:old_client"] = {
            "tokens": 5,
            "last_update": time.time() - 700  # >600s stale
        }
        rl._cleanup_stale_buckets()
        assert "ip:old_client" not in rl._buckets


# ═══════════════════════════════════════════════════════════════════════════════
# CircuitBreaker
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def cb():
    """Fresh CircuitBreaker for each test."""
    return CircuitBreaker(name="test_circuit", failure_threshold=3,
                          recovery_timeout=5, half_open_requests=2)


class TestCircuitBreakerInit:
    def test_starts_closed(self, cb):
        assert cb.state == CircuitState.CLOSED

    def test_starts_with_zero_failures(self, cb):
        assert cb.failure_count == 0

    def test_name_set(self, cb):
        assert cb.name == "test_circuit"


class TestCircuitBreakerShouldAttempt:
    def test_closed_allows(self, cb):
        assert cb._should_attempt() is True

    def test_open_blocks(self, cb):
        cb.state = CircuitState.OPEN
        cb.last_failure_time = time.time()
        assert cb._should_attempt() is False

    def test_open_transitions_to_half_open_after_timeout(self, cb):
        cb.state = CircuitState.OPEN
        cb.last_failure_time = time.time() - 10  # beyond recovery_timeout=5
        result = cb._should_attempt()
        assert result is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_allows(self, cb):
        cb.state = CircuitState.HALF_OPEN
        assert cb._should_attempt() is True


class TestCircuitBreakerRecordSuccess:
    def test_success_resets_failure_count(self, cb):
        cb.failure_count = 2
        cb.record_success()
        assert cb.failure_count == 0

    def test_half_open_success_increments(self, cb):
        cb.state = CircuitState.HALF_OPEN
        cb.half_open_successes = 0
        cb.record_success()
        assert cb.half_open_successes == 1

    def test_half_open_enough_successes_closes(self, cb):
        cb.state = CircuitState.HALF_OPEN
        cb.half_open_successes = 1  # one more needed (half_open_requests=2)
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_closed_success_stays_closed(self, cb):
        cb.record_success()
        assert cb.state == CircuitState.CLOSED


class TestCircuitBreakerRecordFailure:
    def test_failure_increments_count(self, cb):
        cb.record_failure()
        assert cb.failure_count == 1

    def test_failure_sets_last_failure_time(self, cb):
        cb.record_failure()
        assert cb.last_failure_time is not None

    def test_failures_at_threshold_open_circuit(self, cb):
        # failure_threshold=3
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED  # not yet
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_failure_in_half_open_reopens(self, cb):
        cb.state = CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


class TestCircuitBreakerCall:
    def test_call_success_returns_result(self, cb):
        result = cb.call(lambda: 42)
        assert result == 42

    def test_call_records_success(self, cb):
        cb.failure_count = 2
        cb.call(lambda: "ok")
        assert cb.failure_count == 0

    def test_call_failure_records_failure(self, cb):
        def boom():
            raise ValueError("boom")
        with pytest.raises(ValueError):
            cb.call(boom)
        assert cb.failure_count == 1

    def test_call_when_open_raises_circuit_open_error(self, cb):
        cb.state = CircuitState.OPEN
        cb.last_failure_time = time.time()
        with pytest.raises(CircuitOpenError):
            cb.call(lambda: 42)

    def test_call_with_args(self, cb):
        result = cb.call(lambda x, y: x + y, 3, 4)
        assert result == 7

    @pytest.mark.asyncio
    async def test_call_async_success(self, cb):
        async def async_op():
            return "async_result"
        result = await cb.call_async(async_op)
        assert result == "async_result"

    @pytest.mark.asyncio
    async def test_call_async_failure(self, cb):
        async def async_boom():
            raise RuntimeError("async fail")
        with pytest.raises(RuntimeError):
            await cb.call_async(async_boom)
        assert cb.failure_count == 1

    @pytest.mark.asyncio
    async def test_call_async_when_open(self, cb):
        cb.state = CircuitState.OPEN
        cb.last_failure_time = time.time()
        async def async_op():
            return "ok"
        with pytest.raises(CircuitOpenError):
            await cb.call_async(async_op)


class TestCircuitBreakerGetStatus:
    def test_get_status_keys(self, cb):
        status = cb.get_status()
        assert "name" in status
        assert "state" in status
        assert "failure_count" in status
        assert "last_failure" in status

    def test_get_status_name(self, cb):
        assert cb.get_status()["name"] == "test_circuit"

    def test_get_status_state_is_closed(self, cb):
        assert cb.get_status()["state"] == "closed"

    def test_get_status_after_failure(self, cb):
        cb.record_failure()
        status = cb.get_status()
        assert status["failure_count"] == 1
        assert status["last_failure"] is not None

    def test_get_status_no_failure_last_failure_none(self, cb):
        assert cb.get_status()["last_failure"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# get_circuit
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetCircuit:
    def test_creates_new_circuit(self):
        import core.middleware as mw
        mw._circuits.pop("test_svc_new", None)  # clean up
        cb = get_circuit("test_svc_new")
        assert cb is not None
        assert cb.name == "test_svc_new"

    def test_returns_same_circuit_on_second_call(self):
        import core.middleware as mw
        mw._circuits.pop("test_svc_same", None)
        cb1 = get_circuit("test_svc_same")
        cb2 = get_circuit("test_svc_same")
        assert cb1 is cb2

    def test_custom_threshold_applied(self):
        import core.middleware as mw
        mw._circuits.pop("test_custom_thresh", None)
        cb = get_circuit("test_custom_thresh", failure_threshold=10)
        assert cb.failure_threshold == 10


# ═══════════════════════════════════════════════════════════════════════════════
# circuit_protected decorator
# ═══════════════════════════════════════════════════════════════════════════════

class TestCircuitProtectedDecorator:
    def test_sync_function_wrapped(self):
        import core.middleware as mw
        mw._circuits.pop("deco_sync_test", None)

        @circuit_protected("deco_sync_test")
        def my_func(x):
            return x * 2

        assert my_func(5) == 10

    def test_sync_function_failure_recorded(self):
        import core.middleware as mw
        mw._circuits.pop("deco_fail_test", None)
        cb = get_circuit("deco_fail_test", failure_threshold=5)

        @circuit_protected("deco_fail_test")
        def bad_func():
            raise ValueError("fail")

        with pytest.raises(ValueError):
            bad_func()
        assert cb.failure_count == 1

    @pytest.mark.asyncio
    async def test_async_function_wrapped(self):
        import core.middleware as mw
        mw._circuits.pop("deco_async_test", None)

        @circuit_protected("deco_async_test")
        async def async_func():
            return "async_ok"

        result = await async_func()
        assert result == "async_ok"

    @pytest.mark.asyncio
    async def test_async_function_failure_recorded(self):
        import core.middleware as mw
        mw._circuits.pop("deco_async_fail_test", None)
        cb = get_circuit("deco_async_fail_test", failure_threshold=5)

        @circuit_protected("deco_async_fail_test")
        async def async_bad():
            raise RuntimeError("async fail")

        with pytest.raises(RuntimeError):
            await async_bad()
        assert cb.failure_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# CircuitOpenError
# ═══════════════════════════════════════════════════════════════════════════════

class TestCircuitOpenError:
    def test_is_exception(self):
        e = CircuitOpenError("circuit open")
        assert isinstance(e, Exception)

    def test_message(self):
        e = CircuitOpenError("Test circuit is OPEN")
        assert "OPEN" in str(e)
