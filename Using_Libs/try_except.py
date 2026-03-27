# Aprogram that asks the user to enter two numbers and divides the first number by the second.
#  Ask the user to input two numbers.
# Convert the inputs into numbers. 
# Perform the division. 
# Use try / except to handle errors: 
  # If the user enters text instead of a number , display "Invalid input: please enter a number."
  # If the user tries to divide by zero, display "Error: division by zero is not allowed."
  # If the division works correctly, display the result.



# To Ask User for Input
input_1 = input("Enter first number: ")                 # Get input_1
input_2 = input("Enter second number: ")                # Get input_2

try:
    # To Convert Inputs to Numbers
    a = float(input_1)                                  # Convert input_1 to number
    b = float(input_2)                                  # Convert input_2 to number

    # To Perform Division

    result = a / b              

except ValueError:                                      # Error when input is invalid
    print("\nInvalid input: please enter a number")

except ZeroDivisionError:                               # Error when trying to divide by zero
    print("\nError: division by zero is not allowed")

else:                                                   # Successful division displaying result
    print("\nResult is ", result)

