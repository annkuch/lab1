import bcrypt
class Hasher:
    def __init__(self):
        salt = bcrypt.gensalt()
        self.salt = salt

    def __call__(self, password):
        return bcrypt.hashpw(password.encode('ascii'), self.salt)


hasher = Hasher()
users = {'user1': {'pass': hasher("MyPassword1"),
                   'role': 'user'},
         'user2': {'pass': hasher("MyPassword2"),
                   'role': 'user'},
         'adminUser': {'pass': hasher("adminPassword"),
                       'role': 'admin'}
         }
discs = {'A': {'value': "abcd",
               'read': ["user", "admin"],
               'write': ["user", "admin"]},
         'B': {'value': "12345",
               'read': ["user", "admin"],
               'write': ["admin"]},
         'C': {'value': "adminInfo",
               'read': ["admin"],
               'write': ["admin"]}
         }


def getActionsForUser(userName):
    while True:
        print('-' * 70)
        print("Choose the action:")
        print("1 - read disc")
        print("2 - write to disc")
        print("3 - add new user")
        print("4 - logout")
        action = input()
        if (action not in ["1", "2", "3", "4"]):
            print("Sorry, invalid action")
            continue
        action = int(action)
        if action == 1:
            print("Choose the disc name from the list:")
            for discName in discs:
                print(discName)
            discName = input()
            if discs.get(discName) == None:
                print("Sorry, there is no such disc")
                continue
            if users[userName]['role'] not in discs[discName]['read']:
                print("Sorry, you have no read access for this disc")
                continue
            print("Disc " + discName + " contains " + discs[discName]['value'])
        elif action == 2:
            print("Choose the disc name from the list:")
            for discName in discs:
                print(discName)
            discName = input()
            if discs.get(discName) == None:
                print("Sorry, there is no such disc")
                continue
            if users[userName]['role'] not in discs[discName]['write']:
                print("Sorry, you have no write access for this disc")
                continue
            newValue = input("Please, enter the value to assign to this disc\n")
            discs[discName]['value'] = newValue
            print("Disc " + discName + " is assigned with value " + discs[discName]['value'])
        elif action == 3:
            if users[userName]['role'] != 'admin':
                print("Sorry, you have no right to create new users")
                continue
            newUserName = input("Please, enter the name of new user\n")
            if (users.get(newUserName) != None):
                print("Sorry, such user already exists")
                continue
            password = hasher(input("Please, enter the password for user " + newUserName + '\n'))
            role = input("Please, enter user's role: 1 for admin, 2 for common user\n")
            while role not in ["1", "2"]:
                role = input("Please, enter valid value: 1 for admin, 2 for common user\n")
            users[newUserName] = {'pass': password,
                                  'role': 'admin' if role == '1' else 'user'}
            print("New user " + newUserName + " successfully added")
        elif action == 4:
            break


while True:
    print('-' * 70)
    userName = input("Please, enter your login:\n")
    while (users.get(userName) == None):
        userName = input("Sorry, such user does not exist. Please, enter your login:\n")
    password = hasher(input("Please, enter your password\n"))
    if password != users[userName]['pass']:
        print("Incorrect password")
    else:
        getActionsForUser(userName)
getActionsForUser('adminUser')



