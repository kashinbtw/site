from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Enum, Text
import enum

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
# Настройка подключения к базе данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Используем SQLite для простоты
db = SQLAlchemy(app)


# Определение перечислений для ролей и статусов
class Role(enum.Enum):
    USER = 'user'
    ADMIN = 'admin'


class TicketStatus(enum.Enum):
    NEW = 'Новая'
    IN_PROGRESS = 'В работе'
    RESOLVED = 'Решена'
    CLOSED = 'Закрыта'


# Определение моделей базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.Enum(Role), default=Role.USER)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"News('{self.title}', '{self.category}')"


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum(TicketStatus), default=TicketStatus.NEW)

    def __repr__(self):
        return f"Ticket('{self.topic}', '{self.username}', '{self.status}')"


# Создание таблиц в базе данных
with app.app_context():
    db.create_all()

    # Создание пользователей по умолчанию, если они не существуют
    if not User.query.filter_by(username='user').first():
        user = User(username='user', password='userpass', role=Role.USER)
        db.session.add(user)
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='adminpass', role=Role.ADMIN)
        db.session.add(admin)
    db.session.commit()


# Категории новостей и соответствующие страницы
CATEGORIES = {
    'housing': 'Жилищно-коммунальное хозяйство',
    'transport': 'Транспорт',
    'roads': 'Дорожное хозяйство'
}


# Декоратор для проверки авторизации пользователя
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Пожалуйста, войдите в систему.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# Декоратор для проверки прав администратора
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or User.query.filter_by(username=session['username']).first().role != Role.ADMIN:
            flash('Доступ запрещён. Требуются права администратора.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Контекстный процессор для передачи данных пользователей в шаблоны
@app.context_processor
def inject_users():
    users = {user.username: {'password': user.password, 'role': user.role.value} for user in User.query.all()}
    return dict(users=users)


# Маршруты приложения
@app.route('/')
def index():
    news = News.query.all()
    grouped_news = {v: [] for v in CATEGORIES.values()}
    for item in news:
        grouped_news[item.category].append(item)
    return render_template('index.html', grouped_news=grouped_news, categories=list(CATEGORIES.values()))


@app.route('/housing')
def housing():
    category = CATEGORIES['housing']
    news = News.query.filter_by(category=category).all()
    return render_template('housing.html', news=news, category=category)


@app.route('/roads')
def roads():
    category = CATEGORIES['roads']
    news = News.query.filter_by(category=category).all()
    return render_template('roads.html', news=news, category=category)


@app.route('/transport')
def transport():
    category = CATEGORIES['transport']
    news = News.query.filter_by(category=category).all()
    return render_template('transport.html', news=news, category=category)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['username'] = username
            flash('Вы успешно вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('profile'))
        else:
            flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    username = session['username']
    user = User.query.filter_by(username=username).first()
    tickets = Ticket.query.filter_by(username=username).all()
    return render_template('profile.html', username=username, role=user.role.value, tickets=tickets)


@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if request.method == 'POST':
        topic = request.form.get('topic', '').strip()
        description = request.form.get('description', '').strip()
        if not topic or not description:
            flash('Пожалуйста, заполните все поля.', 'warning')
            return redirect(url_for('submit_ticket'))
        username = session['username']
        ticket = Ticket(username=username, topic=topic, description=description)
        db.session.add(ticket)
        db.session.commit()
        flash('Заявка успешно отправлена.', 'success')
        return redirect(url_for('profile'))
    return render_template('submit_ticket.html')


@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')


@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    tickets = Ticket.query.all()
    return render_template('admin_tickets.html', tickets=tickets)


@app.route('/category/<category_name>')
def category_page(category_name):
    if category_name not in CATEGORIES.values():
        abort(404)
    news = News.query.filter_by(category=category_name).all()
    return render_template('category.html', category=category_name, news=news)


@app.route('/admin/news', methods=['GET', 'POST'])
@admin_required
def admin_news():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category')
        if not title or not content or category not in CATEGORIES.values():
            flash('Пожалуйста, заполните все поля и выберите корректный раздел.', 'warning')
            return redirect(url_for('admin_news'))
        new_item = News(title=title, content=content, category=category)
        db.session.add(new_item)
        db.session.commit()
        flash('Новость успешно добавлена.', 'success')
        return redirect(url_for('admin_news'))
    news = News.query.all()
    return render_template('admin_news.html', news=news, categories=list(CATEGORIES.values()))


if __name__ == '__main__':
    app.run(debug=True)
