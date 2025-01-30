from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import logging
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuração de logging
logging.basicConfig(level=logging.DEBUG)

# Adicione esta configuração após a criação do app
app.secret_key = 'sua_chave_secreta_aqui'  # Troque por uma chave secreta segura

# Modelo para o usuário
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(120), nullable=False)
    pedido = db.relationship('Pedido', backref='usuario', uselist=False)

# Modelo para os pedidos
class Pedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    peruca = db.Column(db.String(20))
    tiara = db.Column(db.Integer)
    camisa = db.Column(db.String(2))
    sunga_preta = db.Column(db.Boolean, default=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        try:
            nome = request.form['nome']
            email = request.form['email']
            senha = request.form['senha']
            
            # Verificar se o email já existe
            usuario_existente = Usuario.query.filter_by(email=email).first()
            if usuario_existente:
                flash('Email já cadastrado', 'error')
                return render_template('cadastro.html')
            
            # Hash da senha antes de salvar
            senha_hash = generate_password_hash(senha)
            novo_usuario = Usuario(nome=nome, email=email, senha=senha_hash)
            
            db.session.add(novo_usuario)
            db.session.commit()
            
            app.logger.info(f'Usuário cadastrado com sucesso: {email}')
            # Fazer login automático após o cadastro
            session['usuario_id'] = novo_usuario.id
            session['usuario_nome'] = novo_usuario.nome
            
            return redirect(url_for('lista_blocos'))
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao cadastrar usuário: {str(e)}')
            flash('Erro ao cadastrar usuário', 'error')
            return render_template('cadastro.html')
    
    return render_template('cadastro.html')

@app.route('/selecionar_itens/<int:usuario_id>', methods=['GET', 'POST'])
def selecionar_itens(usuario_id):
    if request.method == 'POST':
        try:
            tiara_valor = int(request.form.get('tiara')) if request.form.get('tiara') else None
            
            pedido = Pedido(
                usuario_id=usuario_id,
                peruca=request.form.get('peruca'),
                tiara=tiara_valor,
                camisa=request.form.get('camisa'),
                sunga_preta=True if request.form.get('sunga_preta') else False
            )
            
            db.session.add(pedido)
            db.session.commit()
            app.logger.info(f'Pedido registrado para usuário {usuario_id}')
            return redirect(url_for('sucesso'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao registrar pedido: {str(e)}')
            return f"Erro ao registrar pedido: {str(e)}", 500
    
    return render_template('selecionar_itens.html', usuario_id=usuario_id)

@app.route('/sucesso')
def sucesso():
    return render_template('sucesso.html')

@app.route('/usuarios')
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        
        usuario = Usuario.query.filter_by(email=email).first()
        
        if usuario and check_password_hash(usuario.senha, senha):
            session['usuario_id'] = usuario.id
            session['usuario_nome'] = usuario.nome
            app.logger.info(f'Login bem-sucedido para: {email}')
            return redirect(url_for('lista_blocos'))
        else:
            app.logger.warning(f'Tentativa de login mal-sucedida para: {email}')
            return render_template('login.html', error='Email ou senha inválidos')
    
    return render_template('login.html')

# Rota para logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/area_protegida')
@login_required
def area_protegida():
    return 'Esta página só pode ser vista por usuários logados'

@app.route('/lista_blocos')
@login_required
def lista_blocos():
    return render_template('lista_blocos.html')

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            app.logger.info('Banco de dados criado com sucesso')
        except Exception as e:
            app.logger.error(f'Erro ao criar banco de dados: {str(e)}')
    
    app.run(debug=True)