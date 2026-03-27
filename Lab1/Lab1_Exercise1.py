# Strong Password Checker
import string

# Function that defines the rules a password must meet to be considered string
def is_strong_password(pwd):
    return(
        len(pwd) >= 8 and                                    # Length ≥ 8
        any(char.isdigit() for char in pwd) and              # at least  number
        any(char.isupper() for char in pwd) and              # at least one uppercase letter
        any(char in string.punctuation for char in pwd)      # at least one special character
    )

# Testing

print(is_strong_password("password"))
print(is_strong_password("Password"))
print(is_strong_password("Password1"))
print(is_strong_password("Password1#"))



