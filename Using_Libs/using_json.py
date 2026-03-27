# A program that creates a dictionary containing name, age, and city, and 
# Saves this information into a file named user.json.

import json

# To Get User Information that will be stored in the dictionary
name = input("Enter your name: ")
age = int(input("Enter your age: "))
city = input("Enter your city: ")

# To Create a Dictionary
user = {
    "name": name,
    "age": age,
    "city": city
}

# To Save the Dictionary to a JSON file
with open("user.json", "w") as file:
    json.dump(user, file)

print("User information saved to user.json")
