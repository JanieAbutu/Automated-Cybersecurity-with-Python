# reports/report.py
def print_report(students):
    # If no students exist
    if not students:
        print("No students found.")
        return
    print("\n--- Report ---")

    for s in students:
        print(f"\n{s.name}")
        # If student has no grades
        if not s.grades:
            print("  No grades yet.")
            continue

        total = 0

        # Print each grade
        for g in s.grades:
            print(f"  {g.subject}: {g.grade}")
            total += g.grade

        # Calculate average
        avg = total / len(s.grades)
        print(f"  Average: {avg:.2f}")

        # Determine letter grade
        if avg >= 90:
            letter = "A"
        elif avg >= 80:
            letter = "B"
        elif avg >= 70:
            letter = "C"
        elif avg >= 60:
            letter = "D"
        else:
            letter = "F"

        print(f"  Letter Grade: {letter}")

def top_student(students):
    """Prints the student with the highest average grade."""
    if not students:
        print("No students found.")
        return

    # Only consider students with at least one grade
    graded_students = [s for s in students if s.grades]
    if not graded_students:
        print("No students have grades yet.")
        return

    # Find the student with the highest average
    top = max(graded_students, key=lambda s: s.average())
    print(f"Top student: {top.name} with average {top.average():.2f} ({top.letter_grade()})")