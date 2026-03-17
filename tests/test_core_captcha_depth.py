# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_captcha_depth.py
# REM: Depth tests for core/captcha.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timedelta, timezone

from core.captcha import (
    CHALLENGE_WORDS,
    CAPTCHAChallenge,
    CAPTCHAManager,
    ChallengeType,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(CAPTCHAManager)
    m._challenges = {}
    return m


# ═══════════════════════════════════════════════════════════════════════════════
# ChallengeType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestChallengeType:
    def test_math_value(self):
        assert ChallengeType.MATH.value == "math"

    def test_text_reverse_value(self):
        assert ChallengeType.TEXT_REVERSE.value == "text_reverse"

    def test_word_scramble_value(self):
        assert ChallengeType.WORD_SCRAMBLE.value == "word_scramble"

    def test_three_types(self):
        assert len(ChallengeType) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# CHALLENGE_WORDS
# ═══════════════════════════════════════════════════════════════════════════════

class TestChallengeWords:
    def test_twenty_words(self):
        assert len(CHALLENGE_WORDS) == 20

    def test_all_lowercase(self):
        for word in CHALLENGE_WORDS:
            assert word == word.lower()

    def test_eligible_for_reverse_exist(self):
        # Text-reverse uses 5-7 letter words
        eligible = [w for w in CHALLENGE_WORDS if 5 <= len(w) <= 7]
        assert len(eligible) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# CAPTCHAManager constants
# ═══════════════════════════════════════════════════════════════════════════════

class TestCAPTCHAManagerConstants:
    def test_max_attempts(self, mgr):
        assert mgr.MAX_ATTEMPTS == 3

    def test_challenge_lifetime_five_minutes(self, mgr):
        assert mgr.CHALLENGE_LIFETIME == timedelta(minutes=5)


# ═══════════════════════════════════════════════════════════════════════════════
# _generate_math
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateMath:
    def test_returns_tuple_of_two(self, mgr):
        result = mgr._generate_math()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_question_is_string(self, mgr):
        question, _ = mgr._generate_math()
        assert isinstance(question, str)

    def test_answer_is_string(self, mgr):
        _, answer = mgr._generate_math()
        assert isinstance(answer, str)

    def test_answer_is_integer_string(self, mgr):
        _, answer = mgr._generate_math()
        assert int(answer) == int(answer)

    def test_question_has_what_is(self, mgr):
        question, _ = mgr._generate_math()
        assert "What is" in question

    def test_question_has_question_mark(self, mgr):
        question, _ = mgr._generate_math()
        assert "?" in question

    def test_answer_is_correct_many_times(self, mgr):
        # Run many times to cover all operators
        for _ in range(30):
            question, answer = mgr._generate_math()
            # Parse a + b, a - b, or a x b
            import re
            m = re.search(r"(\d+) ([+\-x]) (\d+)", question)
            assert m is not None, f"Unexpected question format: {question}"
            a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
            if op == "+":
                assert int(answer) == a + b
            elif op == "-":
                assert int(answer) == a - b
            else:  # x
                assert int(answer) == a * b

    def test_addition_result_non_negative(self, mgr):
        for _ in range(20):
            question, answer = mgr._generate_math()
            if "+" in question:
                assert int(answer) >= 0

    def test_subtraction_result_non_negative(self, mgr):
        for _ in range(30):
            question, answer = mgr._generate_math()
            if " - " in question:
                assert int(answer) >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# _generate_text_reverse
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateTextReverse:
    def test_returns_tuple(self, mgr):
        result = mgr._generate_text_reverse()
        assert isinstance(result, tuple) and len(result) == 2

    def test_answer_is_reversed_word(self, mgr):
        for _ in range(10):
            question, answer = mgr._generate_text_reverse()
            # Extract the word from "Type 'word' backwards"
            import re
            m = re.search(r"'(\w+)'", question)
            assert m is not None
            word = m.group(1)
            assert answer == word[::-1]

    def test_word_in_challenge_words(self, mgr):
        for _ in range(10):
            question, _ = mgr._generate_text_reverse()
            import re
            m = re.search(r"'(\w+)'", question)
            word = m.group(1)
            assert word in CHALLENGE_WORDS

    def test_word_is_5_to_7_chars(self, mgr):
        for _ in range(10):
            question, _ = mgr._generate_text_reverse()
            import re
            m = re.search(r"'(\w+)'", question)
            word = m.group(1)
            assert 5 <= len(word) <= 7

    def test_question_says_backwards(self, mgr):
        question, _ = mgr._generate_text_reverse()
        assert "backwards" in question


# ═══════════════════════════════════════════════════════════════════════════════
# _generate_word_scramble
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateWordScramble:
    def test_returns_tuple(self, mgr):
        result = mgr._generate_word_scramble()
        assert isinstance(result, tuple) and len(result) == 2

    def test_answer_is_in_challenge_words(self, mgr):
        for _ in range(10):
            _, answer = mgr._generate_word_scramble()
            assert answer in CHALLENGE_WORDS

    def test_question_says_unscramble(self, mgr):
        question, _ = mgr._generate_word_scramble()
        assert "Unscramble" in question

    def test_scrambled_is_uppercase(self, mgr):
        for _ in range(10):
            question, _ = mgr._generate_word_scramble()
            import re
            m = re.search(r"Unscramble: (\w+)", question)
            assert m is not None
            scrambled = m.group(1)
            assert scrambled == scrambled.upper()

    def test_scrambled_same_letters_as_answer(self, mgr):
        for _ in range(10):
            question, answer = mgr._generate_word_scramble()
            import re
            m = re.search(r"Unscramble: (\w+)", question)
            scrambled = m.group(1).lower()
            assert sorted(scrambled) == sorted(answer)


# ═══════════════════════════════════════════════════════════════════════════════
# generate_challenge
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateChallenge:
    def test_returns_captcha_challenge(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert isinstance(ch, CAPTCHAChallenge)

    def test_math_type_stored(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert ch.challenge_id in mgr._challenges

    def test_text_reverse_type(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.TEXT_REVERSE)
        assert ch.challenge_type == ChallengeType.TEXT_REVERSE

    def test_word_scramble_type(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.WORD_SCRAMBLE)
        assert ch.challenge_type == ChallengeType.WORD_SCRAMBLE

    def test_default_type_is_math(self, mgr):
        ch = mgr.generate_challenge()
        assert ch.challenge_type == ChallengeType.MATH

    def test_not_solved_initially(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert ch.solved is False

    def test_attempts_zero_initially(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert ch.attempts == 0

    def test_expires_in_future(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert ch.expires_at > datetime.now(timezone.utc)

    def test_expires_approximately_five_minutes(self, mgr):
        before = datetime.now(timezone.utc)
        ch = mgr.generate_challenge(ChallengeType.MATH)
        diff = (ch.expires_at - before).total_seconds()
        assert abs(diff - 300) < 5

    def test_challenge_has_answer(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert len(ch.answer) > 0

    def test_unique_challenge_ids(self, mgr):
        ids = {mgr.generate_challenge(ChallengeType.MATH).challenge_id for _ in range(5)}
        assert len(ids) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# verify_challenge
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyChallenge:
    def test_correct_answer_returns_true(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.verify_challenge(ch.challenge_id, ch.answer) is True

    def test_wrong_answer_returns_false(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.verify_challenge(ch.challenge_id, "wrong") is False

    def test_unknown_id_returns_false(self, mgr):
        assert mgr.verify_challenge("nonexistent", "any") is False

    def test_increments_attempts_on_wrong(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, "wrong")
        assert ch.attempts == 1

    def test_increments_attempts_on_correct(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        assert ch.attempts == 1

    def test_solved_set_on_correct(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        assert ch.solved is True

    def test_already_solved_returns_true(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        # Second call after solved
        assert mgr.verify_challenge(ch.challenge_id, "anything") is True

    def test_expired_challenge_returns_false(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        ch.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert mgr.verify_challenge(ch.challenge_id, ch.answer) is False

    def test_max_attempts_returns_false(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        ch.attempts = CAPTCHAManager.MAX_ATTEMPTS
        assert mgr.verify_challenge(ch.challenge_id, ch.answer) is False

    def test_case_insensitive_comparison(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.TEXT_REVERSE)
        assert mgr.verify_challenge(ch.challenge_id, ch.answer.upper()) is True

    def test_strips_whitespace(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.verify_challenge(ch.challenge_id, f"  {ch.answer}  ") is True


# ═══════════════════════════════════════════════════════════════════════════════
# is_challenge_valid / is_solved / consume_challenge
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsChallengeValid:
    def test_valid_after_creation(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.is_challenge_valid(ch.challenge_id) is True

    def test_invalid_for_unknown(self, mgr):
        assert mgr.is_challenge_valid("nonexistent") is False

    def test_invalid_after_expiry(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        ch.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert mgr.is_challenge_valid(ch.challenge_id) is False

    def test_invalid_after_solved(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        ch.solved = True
        assert mgr.is_challenge_valid(ch.challenge_id) is False

    def test_invalid_after_max_attempts(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        ch.attempts = CAPTCHAManager.MAX_ATTEMPTS
        assert mgr.is_challenge_valid(ch.challenge_id) is False


class TestIsSolved:
    def test_false_before_solving(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.is_solved(ch.challenge_id) is False

    def test_true_after_solving(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        assert mgr.is_solved(ch.challenge_id) is True

    def test_false_for_unknown(self, mgr):
        assert mgr.is_solved("nonexistent") is False


class TestConsumeChallenge:
    def test_returns_false_for_unsolved(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.consume_challenge(ch.challenge_id) is False

    def test_returns_true_for_solved(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        assert mgr.consume_challenge(ch.challenge_id) is True

    def test_removes_from_challenges_after_consume(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        mgr.consume_challenge(ch.challenge_id)
        assert ch.challenge_id not in mgr._challenges

    def test_second_consume_returns_false(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        mgr.verify_challenge(ch.challenge_id, ch.answer)
        mgr.consume_challenge(ch.challenge_id)
        assert mgr.consume_challenge(ch.challenge_id) is False

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.consume_challenge("nonexistent") is False


# ═══════════════════════════════════════════════════════════════════════════════
# cleanup_expired
# ═══════════════════════════════════════════════════════════════════════════════

class TestCleanupExpired:
    def test_returns_zero_when_none_expired(self, mgr):
        mgr.generate_challenge(ChallengeType.MATH)
        assert mgr.cleanup_expired() == 0

    def test_removes_expired_challenge(self, mgr):
        ch = mgr.generate_challenge(ChallengeType.MATH)
        ch.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        mgr.cleanup_expired()
        assert ch.challenge_id not in mgr._challenges

    def test_returns_count_of_removed(self, mgr):
        for _ in range(3):
            ch = mgr.generate_challenge(ChallengeType.MATH)
            ch.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert mgr.cleanup_expired() == 3

    def test_keeps_valid_challenges(self, mgr):
        valid = mgr.generate_challenge(ChallengeType.MATH)
        expired = mgr.generate_challenge(ChallengeType.MATH)
        expired.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        mgr.cleanup_expired()
        assert valid.challenge_id in mgr._challenges

    def test_empty_manager_returns_zero(self, mgr):
        assert mgr.cleanup_expired() == 0
