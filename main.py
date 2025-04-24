from flask import Flask, render_template, redirect, url_for, request, session, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Замените на сложный секретный ключ

# Пример пользователей
users = {
    'user': {'password': 'userpass', 'role': 'user'},
    'admin': {'password': 'adminpass', 'role': 'admin'}
}

# Хранилище заявок (в памяти)
tickets = []
news = []
CATEGORIES = {
    'housing': 'Жилищно-коммунальное хозяйство',
    'transport': 'Транспорт',
    'roads': 'Дорожное хозяйство'
}

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Пожалуйста, войдите в систему.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or users.get(session['username'], {}).get('role') != 'admin':
            flash('Доступ запрещён. Требуются права администратора.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_users():
    return dict(users=users)

@app.route('/')
def index():
    sorted_news = sorted(news, key=lambda x: x['id'], reverse=True)
    # Группируем новости по категориям (названиям)
    grouped_news = {v: [] for v in CATEGORIES.values()}
    for item in sorted_news:
        grouped_news[item['category']].append(item)
    return render_template('index.html', grouped_news=grouped_news, categories=list(CATEGORIES.values()))

@app.route('/housing')
def housing():
    category = CATEGORIES['housing']
    filtered_news = [n for n in news if n['category'] == category]
    filtered_news = sorted(filtered_news, key=lambda x: x['id'], reverse=True)
    return render_template('housing.html', news=filtered_news, category=category)

@app.route('/roads')
def roads():
    category = CATEGORIES['roads']
    filtered_news = [n for n in news if n['category'] == category]
    filtered_news = sorted(filtered_news, key=lambda x: x['id'], reverse=True)
    return render_template('roads.html', news=filtered_news, category=category)

@app.route('/transport')
def transport():
    category = CATEGORIES['transport']
    filtered_news = [n for n in news if n['category'] == category]
    filtered_news = sorted(filtered_news, key=lambda x: x['id'], reverse=True)
    return render_template('transport.html', news=filtered_news, category=category)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user['password'] == password:
            session['username'] = username
            flash('Вы успешно вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('profile'))
        else:
            flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html', users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    username = session['username']
    role = users[username]['role']
    # Получаем заявки текущего пользователя
    user_tickets = [t for t in tickets if t['username'] == username]
    return render_template('profile.html', username=username, role=role, tickets=user_tickets, users=users)

@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if request.method == 'POST':
        topic = request.form.get('topic', '').strip()
        description = request.form.get('description', '').strip()
        if not topic or not description:
            flash('Пожалуйста, заполните все поля.', 'warning')
            return redirect(url_for('submit_ticket'))
        ticket = {
            'id': len(tickets) + 1,
            'username': session['username'],
            'topic': topic,
            'description': description,
            'status': 'Новая'
        }
        tickets.append(ticket)
        flash('Заявка успешно отправлена.', 'success')
        return redirect(url_for('profile'))
    return render_template('submit_ticket.html', users=users)

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', users=users)

@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    return render_template('admin_tickets.html', tickets=tickets, users=users)

@app.route('/category/<category_name>')
def category_page(category_name):
    # Проверяем, что категория валидна (по названию)
    if category_name not in CATEGORIES.values():
        abort(404)
    filtered_news = [n for n in news if n['category'] == category_name]
    filtered_news = sorted(filtered_news, key=lambda x: x['id'], reverse=True)
    return render_template('category.html', category=category_name, news=filtered_news)


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
        new_item = {
            'id': len(news) + 1,
            'title': title,
            'content': content,
            'category': category
        }
        news.append(new_item)
        flash('Новость успешно добавлена.', 'success')
        return redirect(url_for('admin_news'))
    sorted_news = sorted(news, key=lambda x: x['id'], reverse=True)
    return render_template('admin_news.html', news=sorted_news, categories=list(CATEGORIES.values()))

if __name__ == '__main__':
    app.run(debug=True)
