# A program that configures logging with the INFO level, 
# Creates a function divide(a, b)  and 
# Records an INFO log when the division is successful and 
# An ERROR log if the user attempts to divide by zero.

import logging

# To Configure Logging and the format the log appears
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Function to divide (a, b) and output status log
def divide(a, b):
    if b != 0:
        result = a / b
        logging.info(f"Division successful: {a} / {b} = {result}")   #Generate info log for successful diuision
        return result
    else:
        logging.error("Attempted division by Zero.")                 #Generate error log for failed attempt with 0
        return None
    
# To Get Input from User
a = float(input("Enter first number: "))
b = float(input("Enter second number: "))

# Call the function
divide(a, b)
