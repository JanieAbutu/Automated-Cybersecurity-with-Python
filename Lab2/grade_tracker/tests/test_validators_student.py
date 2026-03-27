# tests/test_validators_student.py
import pytest
from utils.validators import validate_grade
from models.student import Student, Grade

# -------------------------------
# validate_grade() tests
# -------------------------------
@pytest.mark.parametrize("value, expected_ok, expected_result", [
    ("50", True, 50.0),
    ("0", True, 0.0),
    ("100", True, 100.0),
    ("-5", False, "Grade must be between 0 and 100."),
    ("105", False, "Grade must be between 0 and 100."),
    ("abc", False, "Invalid grade."),
])
def test_validate_grade(value, expected_ok, expected_result):
    ok, result = validate_grade(value)
    assert ok == expected_ok
    if ok:
        assert result == expected_result
    else:
        assert result == expected_result

# -------------------------------
# Student.letter_grade() tests
# -------------------------------
def test_student_letter_grade():
    s = Student("Alice")
    assert s.letter_grade() is None  # no grades yet

    s.add_grade("Math", 95)
    s.add_grade("Science", 85)
    # average = (95+85)/2 = 90 -> 'A'
    assert s.letter_grade() == "A"

    s2 = Student("Bob")
    s2.add_grade("Math", 75)  # 'C'
    assert s2.letter_grade() == "C"

    s3 = Student("Charlie")
    s3.add_grade("Math", 60)  # 'D'
    s3.add_grade("English", 55)  # avg = 57.5 -> 'F'
    assert s3.letter_grade() == "F"