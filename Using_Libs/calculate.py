## Structuring a Script with Function and Modules

# Function for Addition
def addition(a,b):
    return a + b

# Function for Multiplication
def multiply(a,b):
    return a * b

# Function for Substraction
def substraction(a,b):
    return a - b

# Function to Get Values from user
def get_values():
    a = float(input("Number 1: "))        # Get the first input and convert to number
    b = float(input("Number 2: "))        # Get the second input and convert to number
    return a, b

# Function to Calculate and Store Results
def calc(a,b):
    add_result = addition(a,b)                  # Addition
    mult_result = multiply(a,b)                 # Multiplication
    sub_result = substraction(a,b)              # Division
    return add_result, mult_result, sub_result

#Function to Display Results
def display_results(add_result, mult_result, sub_result):
    print("Addition:", add_result)
    print("Multiplication:", mult_result)
    print("Substraction:", sub_result)

def main():
    a, b = get_values()
    add_result, mult_result, sub_result = calc(a,b)
    display_results(add_result, mult_result, sub_result)

main()