import json
import os
from models.student import Student


class StudentStorage:

    # __init__(filepath) — accepts JSON file path (default 'students.json')
    def __init__(self, filepath="students.json"):
        self.filepath = filepath

    # load() — reads file and returns list of Student objects
    # returns [] if file does not exist
    def load(self):
        if not os.path.exists(self.filepath):
            return []

        with open(self.filepath, "r") as f:
            data = json.load(f)

        # To convert dictionaries to Student objects
        students = [Student.from_dict(s) for s in data]
        return students

    # To save(students) — writes list of Student objects to JSON file
    def save(self, students):
        with open(self.filepath, "w") as f:
            json.dump([s.to_dict() for s in students], f, indent=2)
