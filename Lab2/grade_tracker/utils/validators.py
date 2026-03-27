# To validate_name(name: str)
# Returns (True, '') if valid, or (False, error message)
def validate_name(name: str):
    name = name.strip()

    if not name:
        return (False, "Name cannot be empty.")

    return (True, "")


# To validate_grade(value: str)
# To Parse string to float and checks range 0–100
# Returns (True, float) or (False, error message)
def validate_grade(value: str):

    try:
        grade = float(value)
    except ValueError:
        return (False, "Invalid grade.")

    if grade < 0 or grade > 100:
        return (False, "Grade must be between 0 and 100.")

    return (True, grade)
