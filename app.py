from flask import Flask, request, redirect, jsonify, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import tempfile, ast, os, subprocess

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db?journal_mode=WAL'
db = SQLAlchemy(app)
manager = LoginManager(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_number = db.Column(db.Integer, unique=True)
    correct_answer = db.Column(db.String(255), nullable=False, default='')
class UserTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
class CopyCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    code = db.Column(db.String(1000), nullable=False)
@manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

def flag_change(flag: bool) -> bool:
    return not flag

def remove_symbols(code: str) -> str:
    correct_symbols = "+=-/&|!<>(){}*`[]"
    result = ""
    flag1 = True
    flag2 = True
    for symbol in code:
        if symbol == "'":
            flag1 = flag_change(flag1)
        elif symbol == '"':
            flag2 = flag_change(flag2)
        if flag1 and flag2 and symbol in correct_symbols:
            result += symbol 
    print(result) 
    return result

def max_len(your_code: str, bd_code: str) -> tuple:
    if len(your_code) < len(bd_code):
        return your_code, bd_code
    return bd_code, your_code

def N_gramms(first_code, second_code) -> float:
    print()
    print("N_gramms")
    res = 0.0
    interim_result = 0.0
    max_volume = 0.0
    first_code, second_code = max_len(first_code, second_code)
    if len(first_code) < 4 or len(second_code) < 4:
        print("NO SOLVE")
        return -1
    if len(first_code) / len(second_code) <= 0.6:
        print("NO SOLVE")
        return -1
    if len(second_code) / len(first_code) <= 0.6:
        print("NO SOLVE")
        return -1
    first = list(first_code)
    max_volume = len(second_code) - 2
    for i in range(2, len(first)):
        res_str = "".join([first[j] for j in range(i-2, i+1)])
        print(res_str, "        ", end="")
        if res_str in second_code:
            interim_result += 1
    similarity = (interim_result/max_volume) * 100
    return similarity

def find_similaries(change_code, task_id) -> float:
    strs = CopyCode.query.all()
    results = []
    for str in strs:
        if str.task_id == task_id:
            results.append(N_gramms(str.code, change_code))
            print(results)
    new_copy_code = CopyCode(task_id=task_id, code=change_code)
    db.session.add(new_copy_code)
    db.session.commit()
    return round(sum(results)/len(results) , 3)

def render_task_template1():
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template('/zadanie1.html', user=current_user, task_status=task_status)

def render_task_template2():
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template('/zadanie2.html', user=current_user, task_status=task_status)

def render_task_template3():
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template('/zadanie3.html', user=current_user, task_status=task_status)

def render_task_template4():
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template('/zadanie4.html', user=current_user, task_status=task_status)

def render_task_template5():
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template('/zadanie5.html', user=current_user, task_status=task_status)

app.add_url_rule('/zadanie1', view_func=login_required(render_task_template1), endpoint='task_1')
app.add_url_rule('/zadanie2', view_func=login_required(render_task_template2), endpoint='task_2')
app.add_url_rule('/zadanie3', view_func=login_required(render_task_template3), endpoint='task_3')
app.add_url_rule('/zadanie4', view_func=login_required(render_task_template4), endpoint='task_4')
app.add_url_rule('/zadanie5', view_func=login_required(render_task_template5), endpoint='task_5')

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    tasks = Task.query.all()
    task_status = {}
    for task in tasks:
        user_task = UserTask.query.filter_by(user_id=current_user.id, task_id=task.id).first()
        if user_task:
            task_status[task.task_number] = user_task.completed
        else:
            task_status[task.task_number] = False
    return render_template('zadanie1.html', user=current_user, task_status=task_status)
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
        elif len(login) > 10:
            flash('Логин должен быть не более 10 символов')
        elif password != password2:
            flash('Пароли не совпадают')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

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
    code1 = code
    code_change = remove_symbols(code1)
    input_data = data.get('input')
    task_number = data.get('task_number')

    if not code:
        return jsonify({"error": "Код не вписан"}), 400

    try:
        result = execute_code(code, input_data)
        result2 = str(find_similaries(code_change,task_number)) + "%"
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

        return jsonify({"output": output, "error": error_output, "success": success, "task_completed": task_completed, "code_change": result2})

    except Exception as e:
        return jsonify({"output": "", "error": str(e), "success": False, "code_change": ""}), 400

def execute_code(code, input_data):
    temp_file_name = None
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Call):
                    if node.value.func.id == 'print':
                        if isinstance(node.value.args[0], (ast.Num, ast.Bytes)):
                            return {"output": "", "error": "Код не прошел проверку", "success": False, "code_change": ""}
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
            return {"output": output, "error": error_message, "success": False, "code_change": ""}

        return {"output": output, "error": "", "success": True}

    except subprocess.TimeoutExpired:
        return {"output": "", "error": "Ошибка: превышение времени выполнения", "success": False, "code_change": ""}
    except Exception as e:
        return {"output": "", "error": str(e), "success": False, "code_change": ""}
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
        db.session.commit()
    app.run(debug=True, port=5001)