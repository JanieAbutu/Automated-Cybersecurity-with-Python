# A program that displays the current directory, 
# Lists all files andfolders present, and creates a directory named backup


import os                                                  #Import the os library

# To Display Current Directory
current_directory = os.getcwd()                            #Get the current directory and store in variable
print("\nThe Current Directory is ", current_directory)    #Display the current directory

# To List all files and folders in the Directory
print("\nAll files and folders in the current directory are")

items = os.listdir(current_directory)

for item in items:                                      #Loop through the list and print each item
    print(item)

# To Create a Directory named "Backup"
backup_dir = "backup"                                   #Naming the directory to create

if not os.path.exists(backup_dir):                      #If directory does not exist, create
    os.mkdir(backup_dir)
    print("\nbackup' directory created successfully")

else:                                                    #If directory exists, let the user know
    print ("\n'backup' directory already exists")