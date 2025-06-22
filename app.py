import logging
import traceback
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from sqlalchemy import func
import io
import os
import json
from openpyxl import Workbook
from datetime import timedelta
import pandas as pd
from flask import send_file
import smtplib
from email.mime.text import MIMEText
import smtplib
from email.mime.multipart import MIMEMultipart
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    app.logger.error(f"Exception: {e}\n{tb}")
    return "Внутренняя ошибка сервера. Проверьте логи.", 500

@app.errorhandler(Exception)
def handle_all_exceptions(e):
    tb = traceback.format_exc()
    app.logger.error(f"Exception:\n{tb}")
    return f"<pre>{tb}</pre>", 500

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'g.atayev.mwbbm@gmail.com'     # ← сюда введи свою почту
SMTP_PASSWORD = 'nppp rztg omtv xoqc'        # ← сюда введи пароль приложения Gmail
FROM_EMAIL = 'g.atayev.mwbbm@gmail.com'

@app.route('/test-email')
def test_email():
    try:
        send_email("g.atayev.mwbbm@gmail.com", "Тестовое письмо", "<b>Тестовый контент</b>")
        return "Письмо отправлено"
    except Exception as e:
        return f"Ошибка: {e}"

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    full_name = db.Column(db.String(128))
    email = db.Column(db.String(120), unique=True)
    position = db.Column(db.String(64))
    role = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ReportForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    filename = db.Column(db.String(200))
    questions = db.relationship('ReportQuestion', backref='form', lazy=True)
    answers = db.relationship('ReportAnswer', backref='form', lazy=True)


class ReportQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('report_form.id'), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ReportAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    form_id = db.Column(db.Integer, db.ForeignKey('report_form.id'), nullable=False)
    answers_json = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    note = db.Column(db.Text)  # Примечание администратора
    user = db.relationship('User', backref='answers')

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body, 'html', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.sendmail(FROM_EMAIL, [to_email], msg.as_string())
    except Exception as e:
        app.logger.error(f"Ошибка отправки email: {e}")



# Декоратор
@app.template_filter('localtime')
def localtime_filter(dt):
    if dt is None:
        return ''
    return (dt + timedelta(hours=5)).strftime('%d.%m.%Y %H:%M')

def login_required(role=None):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or (role and session.get('role') != role):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper
	
@app.route('/admin/answers/<int:answer_id>/note', methods=['POST'])
@login_required('admin')
def save_note(answer_id):
    note = request.form.get('note', '').strip()
    answer = ReportAnswer.query.get_or_404(answer_id)
    answer.note = note
    db.session.commit()
    flash('Примечание сохранено')

    teacher = answer.user
    if teacher and teacher.email:
        subject = "Täzeden bellik goşuldy"
        body = f"Hormatly {teacher.full_name},\n\nSiziň '{answer.form.title}' hasabatyňyza primeçaniýe goşuldy:\n\n\"{answer.note}\"\n\nE-hasabat hasabat ulgamy."
        send_email(teacher.email, subject, body)

    return redirect(url_for('view_form_answers', form_id=answer.form_id))


	
@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        email = request.form['email']
        position = request.form['position']
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Пользователь с таким логином или email уже существует')
            return redirect(url_for('add_user'))

        new_user = User(
            username=username,
            full_name=full_name,
            email=email,
            position=position,
            role='teacher'
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Учитель {full_name} добавлен')
        return redirect(url_for('admin_users'))

    return render_template('add_user.html')

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        email = request.form['email']
        position = request.form['position']
        password = request.form.get('password')

        # Проверка на уникальность username и email (кроме текущего пользователя)
        existing_user = User.query.filter(
            ((User.username == username) | (User.email == email)) & (User.id != user_id)
        ).first()
        if existing_user:
            flash('Логин или email уже используются другим пользователем')
            return redirect(url_for('edit_user', user_id=user_id))

        user.username = username
        user.full_name = full_name
        user.email = email
        user.position = position

        if password:
            user.set_password(password)

        db.session.commit()
        flash('Данные учителя обновлены')
        return redirect(url_for('admin_users'))

    return render_template('edit_user.html', user=user)
	
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Учитель удалён')
    return redirect(url_for('admin_users'))
	
@app.route('/admin/users')
@login_required('admin')
def admin_users():
    users = User.query.filter_by(role='teacher').all()
    return render_template('users.html', users=users)
	
	
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard' if user.role == 'admin' else 'teacher_dashboard'))
        else:
            flash('Неверный логин или пароль')
    return render_template('login.html')


	
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Вы вышли из системы')
    return redirect(url_for('login'))
@app.route('/edit_form/<int:form_id>', methods=['GET', 'POST'])
@login_required('admin')
def edit_form(form_id):
    form = ReportForm.query.get_or_404(form_id)

    if request.method == 'POST':
        form.title = request.form['title']
        file = request.files.get('file')

        if file and file.filename:
            filename = datetime.now().strftime('%Y%m%d_%H%M%S_') + file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            form.filename = filename

        # Обновляем существующие вопросы
        for question in form.questions:
            new_text = request.form.get(f'existing_question_{question.id}')
            if new_text:
                question.text = new_text

        # Добавляем новые вопросы (если есть)
        new_qs_raw = request.form.get('new_questions')
        if new_qs_raw:
            try:
                new_qs = json.loads(new_qs_raw)
                for q_text in new_qs:
                    if q_text.strip():
                        db.session.add(ReportQuestion(form_id=form.id, text=q_text.strip()))
            except Exception as e:
                print("Ошибка разбора новых вопросов:", e)

        db.session.commit()
        flash('Форма и вопросы обновлены')
        return redirect(url_for('dashboard'))

    return render_template('edit_form.html', form=form)


	
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    forms = ReportForm.query.order_by(ReportForm.created_at.desc()).all()

    # Для каждой формы вычислим максимальное время ответа
    last_answers = {}
    for form in forms:
        last_answer = db.session.query(func.max(ReportAnswer.updated_at))\
            .filter(ReportAnswer.form_id == form.id).scalar()
        last_answers[form.id] = last_answer

    return render_template('admin_dashboard.html', forms=forms, last_answers=last_answers)

@app.route('/teacher')
@login_required('teacher')
def teacher_dashboard():
    forms = ReportForm.query.order_by(ReportForm.created_at.desc()).all()
    return render_template('teacher_dashboard.html', forms=forms)

@app.route('/form_file/<filename>')
def form_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/add_form', methods=['GET', 'POST'])
@login_required('admin')
def add_form():
    if request.method == 'POST':
        try:
            title = request.form['title']
            file = request.files.get('file')
            filename = None

            if file:
                filename = datetime.now().strftime('%Y%m%d_%H%M%S_') + file.filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            form = ReportForm(title=title, filename=filename)
            db.session.add(form)
            db.session.commit()

            for q_text in request.form.getlist('question'):
                if q_text.strip():
                    question = ReportQuestion(form_id=form.id, text=q_text.strip())
                    db.session.add(question)
            db.session.commit()

            teachers = User.query.filter_by(role='teacher').all()
            subject = "Täze hasabat goşuldy"

            for teacher in teachers:
                if teacher.email:
                    body = f"""
Salam hormatly {teacher.full_name}! Täze '{form.title}' barada hasabat goşuldy.

E-hasabat platformasyna girip, ony doldurmagyňyzy haýyş edýärin!

Link: http://37.220.81.167/
"""
                    send_email(teacher.email, subject, body)

            flash('Hasabat döredildi we mugallymlara habar ugradyldy')
            return redirect(url_for('dashboard'))

        except Exception as e:
            traceback.print_exc()
            return f"❌ Ýalňyşlyk ýüze çykdy: {e}", 500

    return render_template('add_form.html')
	

@app.route('/teacher/forms/<int:form_id>', methods=['GET', 'POST'])
@login_required('teacher')
def teacher_fill_form(form_id):
    form = ReportForm.query.get_or_404(form_id)
    user_id = session['user_id']
    user = User.query.get(user_id)
    answer = ReportAnswer.query.filter_by(form_id=form_id, user_id=user_id).first()

    if request.method == 'POST':
        answers = {str(q.id): request.form.get(f'question_{q.id}', '') for q in form.questions}
        file = request.files.get('file')
        filename = answer.filename if answer else None
        if file and file.filename:
            filename = datetime.now().strftime('%Y%m%d_%H%M%S_') + file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        answers_json = json.dumps(answers, ensure_ascii=False)

        if answer:
            answer.answers_json = answers_json
            answer.filename = filename
            answer.updated_at = datetime.utcnow()
        else:
            answer = ReportAnswer(
                user_id=user_id,
                form_id=form_id,
                answers_json=answers_json,
                filename=filename,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(answer)
        db.session.commit()

        # Отправка уведомления администратору
        admin_email = "g.atayev.mwbbm@gmail.com"  # замените на реальный email администратора
        subject = f"{form.title} hasabaty tabşyrdy: "
        body = f"""
        Hormatly G.Ataýew,

        {user.full_name}   {form.title} barada hasabaty doldurdy.

 
        Hormatlar bilen,
        E-hasabat ulgamy
        """
        send_email(admin_email, subject, body)

        flash('Jogap ýatda saklandy we hünärmen habarly edildi.')
        return redirect(url_for('teacher_dashboard'))

    existing_answers = json.loads(answer.answers_json) if answer else {}

    return render_template(
        'teacher_fill_form.html',
        form=form,
        existing_answers=existing_answers,
        answer=answer,
        questions=form.questions
    )

@app.before_request
def log_request_info():
    app.logger.debug(f"Request: {request.method} {request.url}")
    app.logger.debug(f"Headers: {request.headers}")
    app.logger.debug(f"Body: {request.get_data()}")


@app.route('/admin/forms/<int:form_id>/answers')
@login_required('admin')
def view_form_answers(form_id):
    form = ReportForm.query.get_or_404(form_id)
    users = User.query.filter_by(role='teacher').all()
    answers = ReportAnswer.query.filter_by(form_id=form_id).all()

    import json
    answer_map = {}
    answer_objs = {}
    for a in answers:
        try:
            answer_map[a.user_id] = json.loads(a.answers_json)
            answer_objs[a.user_id] = a
        except:
            answer_map[a.user_id] = {}

    return render_template('view_answers.html', form=form, users=users, answer_map=answer_map, answer_objs=answer_objs)


@app.route('/export_form/<int:form_id>')
@login_required('admin')
def export_form(form_id):
    form = ReportForm.query.get_or_404(form_id)
    answers = ReportAnswer.query.filter_by(form_id=form_id).all()
    questions = {q.id: q.text for q in form.questions}

    rows = []
    for a in answers:
        try:
            answer_dict = json.loads(a.answers_json)
        except:
            answer_dict = {}

        row = {
            'ФИО': a.user.full_name,
            'Email': a.user.email,
            'Дата': a.updated_at.strftime('%d.%m.%Y %H:%M') if a.updated_at else ''
        }
        for q_id, text in questions.items():
            row[text] = answer_dict.get(str(q_id), '')
        rows.append(row)

    df = pd.DataFrame(rows)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    output.seek(0)

    response = make_response(output.read())
    response.headers["Content-Disposition"] = f"attachment; filename=form_{form_id}_answers.xlsx"
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return response

@app.route('/delete_form/<int:form_id>', methods=['POST'])
@login_required('admin')
def delete_form(form_id):
    form = ReportForm.query.get_or_404(form_id)
    
    # Удаляем связанные вопросы и ответы
    ReportQuestion.query.filter_by(form_id=form_id).delete()
    ReportAnswer.query.filter_by(form_id=form_id).delete()
    
    # Удаляем саму форму
    db.session.delete(form)
    db.session.commit()
    flash('Форма удалена.')
    return redirect(url_for('dashboard'))
	
	
@app.route('/init_admin')
def init_admin():
    if not User.query.filter_by(role='admin').first():
        admin = User(
            username='admin',
            full_name='Администратор',
            email='g.atayev.mwbbm@gmail.com',
            position='Завуч',
            role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        return 'Администратор создан. Логин: admin, Пароль: admin123'
    return 'Администратор уже существует.'

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)