from flask import Flask, request, redirect, jsonify, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import tempfile, ast, os, subprocess

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
db = SQLAlchemy(app)
manager = LoginManager(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_number = db.Column(db.Integer, unique=True, nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)

class UserTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)

@manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return None

with app.app_context():
    db.create_all()


def render_task_template(task_number, template_name):
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template(template_name, user=current_user, task_status=task_status)

for i in range(1, 46):
    prefix = next((prefix for threshold, prefix in [(5, 'pr1'), (10, 'pr2'), (15, 'pr3'), (20, 'pr4'), (25, 'pr5'), (30, 'pr6'), (35, 'pr7'), (40, 'pr8'), (45, 'pr9')] if i <= threshold), 'default_prefix')
    endpoint = f'task_{i}'
    app.add_url_rule(f'/{prefix}/zadanie{i%5+1}', view_func=login_required(lambda task_number=i, template=f'{prefix}/{prefix}zadanie{i%5+1}.html': render_task_template(task_number, template)), endpoint=endpoint)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        if not login or not password:
            flash('Проверьте поля логина и пароля')
        else:
            user = User.query.filter_by(login=login).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                next_page = request.args.get('next')
                if not next_page or next_page == url_for('login_page'):
                    next_page = url_for('index')
                return redirect(next_page)
            else:
                flash('Логин или пароль не корректны')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Заполните все поля')
        elif password != password2:
            flash('Пароли не совпадают')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()
            populate_user_tasks()
            return redirect(url_for('login_page'))

    return render_template('register.html')

@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)
    return response

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Вы вышли из аккаунта')
    return redirect(url_for('index'))

@app.route('/run', methods=['POST'])
@login_required
def run_code():
    data = request.json
    code = data.get('code')
    input_data = data.get('input')
    task_number = data.get('task_number')

    if not code:
        return jsonify({"error": "Код не вписан"}), 400

    try:
        result = execute_code(code, input_data)
        output = result['output']
        error_output = result['error']
        success = result['success']
        task_completed = False
        if success:
            task = Task.query.filter_by(task_number=task_number).first()

            if task:
                if output.strip() == task.correct_answer:
                    user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
                    if user_task:
                        user_task.completed = True
                    else:
                        new_user_task = UserTask(user_id=current_user.id, task_id=task.id, completed=True)
                        db.session.add(new_user_task)

                    db.session.commit()
                    task_completed = True

        return jsonify({"output": output, "error": error_output, "success": success, "task_completed": task_completed})

    except Exception as e:
        return jsonify({"output": "", "error": str(e), "success": False}), 400
    

def execute_code(code, input_data):
    temp_file_name = None
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Call):
                    if node.value.func.id == 'print':
                        if isinstance(node.value.args[0], (ast.Num, ast.Bytes)):
                            return {"output": "", "error": "Код не прошел проверку", "success": False}
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='w', encoding='utf-8') as temp_file:
            temp_file.write(code)

            if input_data:
                temp_file.write(f"\ninput_data = '{input_data}'\n")

            temp_file_name = temp_file.name

        result = subprocess.run(['python', temp_file_name], capture_output=True, text=True, timeout=5, input=input_data, encoding='utf-8')

        output = result.stdout
        error_output = result.stderr

        if result.returncode!= 0:
            error_message = "Ошибка: " + (error_output if error_output else "Неизвестная ошибка")
            return {"output": output, "error": error_message, "success": False}

        return {"output": output, "error": "", "success": True}

    except subprocess.TimeoutExpired:
        return {"output": "", "error": "Ошибка: превышение времени выполнения", "success": False}
    except Exception as e:
        return {"output": "", "error": str(e), "success": False}
    finally:
        if temp_file_name and os.path.exists(temp_file_name):
            os.remove(temp_file_name)

def populate_user_tasks():
    users = User.query.all()
    tasks = Task.query.all()
    for user in users:
        for task in tasks:
            user_task = UserTask.query.filter_by(user_id=user.id, task_id=task.id).first()
            if not user_task:
                new_user_task = UserTask(user_id=user.id, task_id=task.id, completed=False)
                db.session.add(new_user_task)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        populate_user_tasks()
    app.run(debug=True, port=5001)