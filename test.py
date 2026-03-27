

try:
    # Ask user for input
    num1 = input("Enter the first number: ")
    num2 = input("Enter the second number: ")

    # Convert inputs to numbers
    a = float(num1)
    b = float(num2)

    # Perform division
    result = a / b

except ValueError:
    print("Invalid input: please enter a number.")

except ZeroDivisionError:
    print("Error: division by zero is not allowed.")

else:
    # Runs only if no error occurred
    print("Result:", result)