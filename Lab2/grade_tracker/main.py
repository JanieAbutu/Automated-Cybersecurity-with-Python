from storage.json_storage import StudentStorage
from models.student import Student
from utils.validators import validate_name, validate_grade
from reports.report import print_report, top_student


# Helper: to find a student by name
def find_student(students, name):
    for s in students:
        if s.name.lower() == name.lower():
            return s
    return None


# To add_student() helper using validator
def add_student(students):
    name = input("Student name: ")

    ok, result = validate_name(name)
    if not ok:
        print(result)
        return

    name = name.strip()

    if find_student(students, name):
        print("Student already exists.")
        return

    students.append(Student(name))
    print(f"Added {name}.")


# To add_grade() helper using validators
def add_grade(students):
    name = input("Student name: ").strip()

    student = find_student(students, name)
    if not student:
        print("Student not found.")
        return

    # To validate grade input
    ok, grade_result = validate_grade(input("Grade (0-100): "))
    if not ok:
        print(grade_result)
        return
    grade = grade_result

    # To validate subject input
    subject = input("Subject: ").strip()
    ok, subject_result = validate_name(subject)
    if not ok:
        print(subject_result)
        return

    # To add grade
    student.add_grade(subject, grade)
    print("Grade added.")

# To delete an existing student
def delete_student(students):
    name = input("Student name to delete: ").strip()
    student = find_student(students, name)
    if not student:
        print("Student not found.")
        return
    students.remove(student)
    print(f"Deleted student '{name}'.")

def main():

    # To instantiate storage and load data
    storage = StudentStorage()
    students = storage.load()

    while True:
        print("\n=== Student Grade Tracker ===")
        print("1. Add student")
        print("2. Add grade")
        print("3. View report")
        print("4. Delete student")
        print("5. Top student")
        print("6. Save and exit")

        choice = input("Choose: ").strip()

        if choice == "1":
            add_student(students)

        elif choice == "2":
            add_grade(students)

        # To call report module
        elif choice == "3":
            print_report(students)

        # To delete
        elif choice == "4":
            delete_student(students)
        
         # To get top students
        elif choice == "5":
            top_student(students)

         # To save on exit
        elif choice == "6":
            storage.save(students)
            print("Saved. Goodbye!")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
