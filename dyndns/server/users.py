import argparse
import getpass
import hashlib
import json
import os
from base64 import standard_b64encode, standard_b64decode


def update_password(user: dict, password: str):
    salt = os.urandom(32) # A new salt for this user
    password_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    user['salt'] = standard_b64encode(salt).decode('ascii')
    user['password'] = standard_b64encode(password_bytes).decode('ascii')

def is_password_correct(user: dict, password: str):
    salt = standard_b64decode(user['salt'])
    stored_password_hash = standard_b64decode(user['password'])
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return stored_password_hash == password_hash

def authenticate(userconfig: str, userid: str, password: str):
    with open(userconfig, "r") as users_file:
        users = json.load(users_file)
    if userid in users:
        return is_password_correct(users[userid], password)
    return False

def update(userconfig: str, userid: str, domainconfig: str):
    mode = 'r+'
    if not os.path.exists(userconfig):
        mode = 'w+'
    try:
        with open(userconfig, mode) as users_file:
            try:
                existing_config = json.load(users_file)
            except ValueError:
                existing_config = {}
            if userid in existing_config:
                user = existing_config[userid]
                user['domainconfig'] = domainconfig
            else:
                password = getpass.getpass("Please input password for user {}:".format(userid))
                user = {'domainconfig': domainconfig}
                print(user)
                update_password(user, password)
                print(user)
            existing_config.update({
                userid: user
            })

            users_file.seek(0)
            users_file.truncate()
            json.dump(existing_config, users_file, sort_keys=True, indent=1)
            return "User {} has been successfully configured.".format(userid)
    except Exception as e:
        return "Could not store user config: {}".format(e)

def password(userconfig: str, userid: str):
    mode = 'r+'
    try:
        with open(userconfig, mode) as users_file:
            existing_config = json.load(users_file)
            user = existing_config[userid]

            password = getpass.getpass("Please input password for user {}:".format(userid))
            update_password(user, password)

            existing_config.update({
                userid: user
            })

            users_file.seek(0)
            users_file.truncate()
            json.dump(existing_config, users_file, sort_keys=True, indent=1)
            return "User {} has been successfully configured.".format(userid)
    except Exception as e:
        return "Could not store user config: {}".format(e)

def remove(userconfig: str, userid: str):
    mode = 'r+'
    try:
        with open(userconfig, mode) as users_file:
            existing_config = json.load(users_file)
            existing_config.remove(userid)

            users_file.seek(0)
            users_file.truncate()
            json.dump(existing_config, users_file, sort_keys=True, indent=1)
            return "User {} has been successfully configured.".format(userid)
    except Exception as e:
        return "Could not store user config: {}".format(e)

def main():
    parser = argparse.ArgumentParser(description="Manage users for Domain Connect DynDNS Update Server")

    parser.add_argument('action', choices=['add', 'update', 'remove', 'password'], help="action to be performed on user configuration")
    parser.add_argument('--userconfig', type=str, default='users.txt', help="user configuration file to update")
    parser.add_argument('--user', type=str, default=None, help="user id to configure")
    parser.add_argument('--domainconfig', type=str, default=None, help="domain-connect-dyndns domain configuration for this user")

    args = parser.parse_args()

    action = args.action
    userconfig = args.userconfig
    user = args.user
    domainconfig = args.domainconfig

    if domainconfig and (action != 'add' and action != 'update'):
        print("--domainconfig only valid with add or update action")
        return

    if action == 'add' or action == 'update':
        print(update(userconfig, user, domainconfig))
    elif action == 'remove':
        print(remove(userconfig, user))
    elif action == 'password':
        print(password(userconfig, user))


if __name__ == "__main__":
    main()
