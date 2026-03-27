# Create two classes Grade and Student
from datetime import datetime           # import library to capture date

# To represent a single grade for a subject
class Grade:
    def __init__(self, subject: str, grade: float, date=None):
        self.subject = subject
        self.grade = grade
        self.date = date or datetime.now().isoformat()
    
     # To convert Grade object to dictionary for JSON storage
    def to_dict(self):
        return {
            "subject": self.subject,
            "grade": self.grade,
            "date": self.date
        }
    
    # To create Grade object from dictionary
    @staticmethod
    def from_dict(data):
        return Grade(data["subject"], data["grade"], data["date"])

# To represent a student with multiple grades
class Student:
    def __init__(self, name: str, grades=None, added=None):
        self.name = name
        self.grades = grades or []
        self.added = added or datetime.now().isoformat()

    # To add a new grade to the student
    def add_grade(self, subject, grade):
        self.grades.append(Grade(subject, grade))

    # To calculate the average grade for the student
    def average(self):
        if not self.grades:
            return None
        return sum(g.grade for g in self.grades) / len(self.grades)

    # To return the letter grade based on average
    def letter_grade(self):
        avg = self.average()
        if avg is None:
            return None
        if avg >= 90:
            return "A"
        elif avg >= 80:
            return "B"
        elif avg >= 70:
            return "C"
        elif avg >= 60:
            return "D"
        return "F"
    
    # To convert Student object to dictionary for JSON storage
    def to_dict(self):
        return {
            "name": self.name,
            "added": self.added,
            "grades": [g.to_dict() for g in self.grades]
        }

    # To create Student object from dictionary
    @staticmethod
    def from_dict(data):
        grades = [Grade.from_dict(g) for g in data["grades"]]
        return Student(data["name"], grades, data["added"])
