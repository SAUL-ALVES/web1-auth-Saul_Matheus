import json

USERS_FILE = 'src/users.json'

def load_users():
    """Lê o arquivo JSON e retorna a lista de usuários."""
    try:
        with open(USERS_FILE, 'r', encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_users(users_list):
    """Salva a lista de usuários no arquivo JSON."""
    with open(USERS_FILE, 'w', encoding="utf-8") as f:
        json.dump(users_list, f, indent=2, ensure_ascii=False)

def find_user(username):
    """Busca um usuário pelo username."""
    users = load_users()
    for user in users:
        if user['username'] == username:
            return user
    return None

def add_user(username, password, role="user"):
    """Adiciona um novo usuário, evitando duplicatas."""
    users = load_users()
    if find_user(username):
        
        return None

  
    new_id = max([user['id'] for user in users] + [0]) + 1

    new_user = {
        "id": new_id,
        "username": username,
        "password": password,
        "role": role
    }

    users.append(new_user)
    save_users(users)
    return new_user