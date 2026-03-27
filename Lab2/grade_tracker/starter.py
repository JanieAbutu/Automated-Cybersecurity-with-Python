import json
import os
from datetime import datetime
 
DATA_FILE = "students.json"
 
def main():
    students = []
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            students = json.load(f)
 
    while True:
        print("\n=== Student Grade Tracker ===")
        print("1. Add student")
        print("2. Add grade")
        print("3. View report")
        print("4. Save and exit")
        choice = input("Choose: ").strip()
 
        if choice == "1":
            name = input("Student name: ").strip()
            if not name:
                print("Name cannot be empty.")
                continue
            for s in students:
                if s["name"].lower() == name.lower():
                    print("Student already exists.")
                    break
            else:
                students.append({"name": name, "grades": [], "added": datetime.now().isoformat()})
                print(f"Added {name}.")
 
        elif choice == "2":
            name = input("Student name: ").strip()
            student = next((s for s in students if s["name"].lower() == name.lower()), None)
            if not student:
                print("Student not found.")
                continue
            try:
                grade = float(input("Grade (0-100): "))
                if grade < 0 or grade > 100:
                    print("Grade must be between 0 and 100.")
                    continue
                subject = input("Subject: ").strip()
                if not subject:
                    print("Subject cannot be empty.")
                    continue
                student["grades"].append({"subject": subject, "grade": grade, "date": datetime.now().isoformat()})
                print("Grade added.")
            except ValueError:
                print("Invalid grade.")
 
        elif choice == "3":
            if not students:
                print("No students found.")
                continue
            print("\n--- Report ---")
            for s in students:
                print(f"\n{s['name']}")
                if not s["grades"]:
                    print("  No grades yet.")
                else:
                    total = sum(g["grade"] for g in s["grades"])
                    avg = total / len(s["grades"])
                    for g in s["grades"]:
                        print(f"  {g['subject']}: {g['grade']}")
                    print(f"  Average: {avg:.2f}")
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
 
        elif choice == "4":
            with open(DATA_FILE, "w") as f:
                json.dump(students, f, indent=2)
            print("Saved. Goodbye!")
            break
 
        else:
            print("Invalid choice.")
 
if __name__ == "__main__":
    main()