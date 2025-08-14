# Autenticação + Gerenciamento de Usuários (Flask)

## Visão Geral
Sistema em Flask com:
- Login por Sessão, JWT e Basic Auth.
- Gerenciamento de usuários via arquivo `users.json`.
- Páginas protegidas e controle de acesso por `role`.

## Como Executar
```bash
# 1. Clone o repositório
git clone [https://github.com/](https://github.com/)SAUL-ALVES/web1-auth-Saul_Matheus.git
cd web1-auth-Saul_Matheus

# 2. Crie e ative o ambiente virtual
python -m venv venv
# No Windows:
# venv\Scripts\activate
# No Linux/macOS:
source venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure as variáveis de ambiente
cp .env.example .env
# ABRA O ARQUIVO .env E EDITE OS SEGREDOS!

# 5. Rode a aplicação
flask run