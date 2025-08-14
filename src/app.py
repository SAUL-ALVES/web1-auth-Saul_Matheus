# -*- coding: utf-8 -*-


import logging
from functools import wraps
import jwt
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash


import config
import helper


logging.basicConfig(level=config.LOG_LEVEL)

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config['SECRET_KEY'] = config.FLASK_SECRET_KEY


def admin_required(f):
    """Decorator que verifica se o usuário é admin (via sessão)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        
        if 'user_id' not in session:
            return jsonify({'message': 'Acesso negado: faça login.'}), 401

        users = helper.load_users()
        user_id = session['user_id']
        user = next((u for u in users if u['id'] == user_id), None)

        
        if not user or user.get('role') != 'admin':
            logging.warning(f'Tentativa de acesso não autorizado à rota de admin pelo usuário ID {user_id}.')
            return jsonify({'message': 'Acesso negado: requer privilégios de administrador.'}), 403

        
        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def index():
    """Rota inicial que renderiza a página de boas-vindas."""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Rota de login que lida com formulário e autentica o usuário."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        logging.debug(f'Tentativa de login para usuário "{username}" do IP {request.remote_addr}. Senha: [MASCARADA]')
        user = helper.find_user(username)

        if user and user['password'] == password:
            
            session['user_id'] = user['id']

            
            payload = {
                'user_id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'exp': datetime.utcnow() + timedelta(minutes=config.JWT_EXPIRES_MIN)
            }
            token = jwt.encode(payload, config.JWT_SECRET, algorithm='HS256')

            logging.debug(f'Login bem-sucedido para "{username}". JWT gerado com payload: {payload}')
            
           
            flash(f'Login bem-sucedido! Seu token JWT é: {token}', 'info')
            return redirect(url_for('dashboard'))
        else:
            logging.debug(f'Falha no login para usuário "{username}": credenciais inválidas.')
            flash('Usuário ou senha inválidos!', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Rota protegida que verifica autenticação por Sessão, JWT ou Basic Auth."""
    current_user = None

    
    if 'user_id' in session:
        users = helper.load_users()
        user_id = session['user_id']
        current_user = next((u for u in users if u['id'] == user_id), None)
        if current_user:
            logging.debug(f'Acesso ao dashboard via SESSÃO pelo usuário: {current_user["username"]}')

    
    auth_header = request.headers.get('Authorization')
    if not current_user and auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, config.JWT_SECRET, algorithms=['HS256'])
            users = helper.load_users()
            current_user = next((u for u in users if u['id'] == payload['user_id']), None)
            if current_user:
                logging.debug(f'Acesso ao dashboard via JWT pelo usuário: {current_user["username"]}')
        except jwt.ExpiredSignatureError:
            logging.debug('Acesso negado: Token JWT expirou.')
            return jsonify({'message': 'Token expirou!'}), 401
        except jwt.InvalidTokenError:
            logging.debug('Acesso negado: Token JWT inválido.')
            return jsonify({'message': 'Token inválido!'}), 401

    
    if not current_user and request.authorization:
        auth = request.authorization
        user = helper.find_user(auth.username)
        if user and user['password'] == auth.password:
            current_user = user
            logging.debug(f'Acesso ao dashboard via BASIC AUTH pelo usuário: {current_user["username"]}')

   
    if not current_user:
        logging.debug('Acesso ao dashboard negado: Nenhuma autenticação válida encontrada.')
        flash('Você precisa fazer login para acessar esta página.', 'warning')
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
def logout():
    """Limpa a sessão do usuário e o redireciona para a página inicial."""
    session.clear()
    return redirect(url_for('index'))


# --- ROTAS DE GERENCIAMENTO DE USUÁRIOS ---

@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    """(Admin) Lista todos os usuários, sem a senha."""
    users = helper.load_users()
    for user in users:
        del user['password']
    return jsonify(users)

@app.route('/users', methods=['POST'])
def create_user():
    """Cria um novo usuário (rota pública conforme especificado)."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Dados incompletos (requer username e password).'}), 400

    new_user = helper.add_user(data['username'], data['password'], data.get('role', 'user'))

    if not new_user:
        return jsonify({'message': 'Usuário já existe.'}), 409

    del new_user['password']
    return jsonify(new_user), 201

@app.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """(Admin) Remove um usuário pelo ID."""
    users = helper.load_users()
    user_to_delete = next((u for u in users if u['id'] == user_id), None)

    if not user_to_delete:
        return jsonify({'message': 'Usuário não encontrado.'}), 404
    
   
    if user_to_delete['id'] == session.get('user_id'):
         return jsonify({'message': 'Admin não pode se auto-remover.'}), 403

    users.remove(user_to_delete)
    helper.save_users(users)

    return jsonify({'message': f'Usuário {user_to_delete["username"]} removido.'}), 200