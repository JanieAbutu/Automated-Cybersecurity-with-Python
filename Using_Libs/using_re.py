# A program that asks the user for an email address, 
# Verifies whether the email is valid using a regular expression, and 
# Displays “Valid email” or “Invalid email.”

import re

# To Ask the User for Email Address
email = input("Please enter your email address: ")


# Regular Expression Pattern for Email Address Validation
#capturing alphanumeric for userinfo, @ and . symbol, alphabets for domain name & extension

regex_pattern = r"\w+@[a-zA-Z]+\.[a-zA-Z]+"          

# Verifying the Validity of the Email Address with Regular Expression
if re.match(regex_pattern, email):
    print("Valid Email Address")               # Displays Valid Email Address if valid
else:
    print("Invald Email Address")              # Displays Invalid Email Address if not valid 