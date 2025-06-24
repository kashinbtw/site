from flask import Flask, render_template, redirect, url_for, request, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging
from functools import wraps
from sqlalchemy import Column, Integer, String, Enum, Text, Float
import enum
import os
from werkzeug.utils import secure_filename
import folium
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
# Настройка подключения к базе данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Используем SQLite для простоты
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Определение перечислений для ролей и статусов
class Role(enum.Enum):
    USER = 'user'
    ADMIN = 'admin'


class TicketStatus(enum.Enum):
    NEW = 'Новая'
    IN_PROGRESS = 'В работе'
    RESOLVED = 'Решена'
    CLOSED = 'Закрыта'


# Категории новостей и соответствующие страницы
CATEGORIES = {
    'housing': 'Жилищно-коммунальное хозяйство',
    'transport': 'Транспорт',
    'roads': 'Дорожное хозяйство'
}

# Определение моделей базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.Enum(Role), default=Role.USER)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"


class InfrastructureObject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # road, transport, housing
    description = db.Column(db.Text, nullable=True)
    address = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    photos = db.relationship('Photo', backref='infrastructure', lazy=True)
    tickets = db.relationship('Ticket', backref='infrastructure', lazy=True)

    def __repr__(self):
        return f"InfrastructureObject('{self.name}', '{self.type}')"


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    infrastructure_id = db.Column(db.Integer, db.ForeignKey('infrastructure_object.id'), nullable=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.Text, nullable=False)
    contact_person = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum(TicketStatus), default=TicketStatus.NEW)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_comment = db.Column(db.Text, nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    infrastructure_id = db.Column(db.Integer, db.ForeignKey('infrastructure_object.id'), nullable=True)
    photos = db.relationship('Photo', backref='ticket', lazy=True)

    def __repr__(self):
        return f"Ticket('{self.topic}', '{self.username}', '{self.status}')"

    @property
    def status_label(self):
        # Возвращает человекочитаемое значение статуса
        return self.status.value


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    image_path = db.Column(db.String(200), nullable=True)
    comments = db.relationship('Comment', backref='news', lazy=True)

    def __repr__(self):
        return f"News('{self.title}', '{self.category}')"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(20), nullable=False)
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), nullable=False)

    def __repr__(self):
        return f"Comment('{self.username}', '{self.date}')"


# Создание таблиц в базе данных
with app.app_context():
    # Удаляем все таблицы
    db.drop_all()
    
    # Создаем все таблицы
    db.create_all()
    
    # Создаем пользователей
    user = User(username='user', password='userpass', role=Role.USER)
    admin = User(username='admin', password='adminpass', role=Role.ADMIN)
    db.session.add(user)
    db.session.add(admin)
    db.session.commit()
    
    # Создаем тестовые объекты инфраструктуры
    test_infrastructure = [
        InfrastructureObject(
            name='Центральный парк',
            type='housing',
            description='Главный парк города с детскими площадками и зонами отдыха',
            address='ул. Ленина, 15, кв. 45',
            latitude=51.2295,
            longitude=58.4751
        ),
        InfrastructureObject(
            name='Автовокзал',
            type='transport',
            description='Междугородний автовокзал',
            address='ул. Советская, 20',
            latitude=51.2312,
            longitude=58.4789
        ),
        InfrastructureObject(
            name='Проспект Мира',
            type='road',
            description='Главная улица города',
            address='пр. Мира, 8',
            latitude=51.2287,
            longitude=58.4732
        ),
        InfrastructureObject(
            name='Железнодорожный вокзал',
            type='transport',
            description='Железнодорожный вокзал станции Орск',
            address='ул. Гагарина, 25',
            latitude=51.2278,
            longitude=58.4765
        ),
        InfrastructureObject(
            name='Торговый центр "Орск"',
            type='housing',
            description='Крупный торговый центр',
            address='ул. Ленина, 15, кв. 45',
            latitude=51.2301,
            longitude=58.4743
        )
    ]
    
    # Добавляем объекты инфраструктуры
    for obj in test_infrastructure:
        db.session.add(obj)
    db.session.commit()
    
    # Добавляем тестовые новости
    test_news = [
        # ЖКХ
        News(
            title='Ремонт теплотрассы на ул. Ленина',
            content='В связи с плановыми работами по ремонту теплотрассы на ул. Ленина, 15-17 июня будет ограничено горячее водоснабжение в домах №10-25. Ремонтные работы продлятся с 9:00 до 18:00.',
            category=CATEGORIES['housing'],
            date=datetime.utcnow()
        ),
        News(
            title='Обновление детских площадок в микрорайоне',
            content='В рамках программы благоустройства городской среды в микрорайоне "Северный" началась установка новых детских площадок. Работы планируется завершить к началу летнего сезона.',
            category=CATEGORIES['housing'],
            date=datetime.utcnow()
        ),
        # Транспорт
        News(
            title='Изменение маршрута автобуса №5',
            content='С 20 июня автобусный маршрут №5 будет временно изменен в связи с ремонтом дорожного покрытия на ул. Советской. Временная остановка будет организована на ул. Пушкина.',
            category=CATEGORIES['transport'],
            date=datetime.utcnow()
        ),
        News(
            title='Новый автобусный парк',
            content='В город поступили 10 новых автобусов большой вместимости. Они будут задействованы на маршрутах №1, №3 и №7, что позволит улучшить качество обслуживания пассажиров.',
            category=CATEGORIES['transport'],
            date=datetime.utcnow()
        ),
        # Дороги
        News(
            title='Ремонт проспекта Мира',
            content='Начался капитальный ремонт проспекта Мира. Работы будут проводиться в ночное время с 23:00 до 6:00. Проезд будет осуществляться по временной схеме движения.',
            category=CATEGORIES['roads'],
            date=datetime.utcnow()
        ),
        News(
            title='Установка новых светофоров',
            content='В рамках программы повышения безопасности дорожного движения на перекрестке ул. Гагарина и пр. Ленина установлены новые светофорные объекты с табло обратного отсчета.',
            category=CATEGORIES['roads'],
            date=datetime.utcnow()
        )
    ]
    
    # Добавляем новости
    for news in test_news:
        db.session.add(news)
    db.session.commit()
    
    # Добавляем тестовые заявки
    test_tickets = [
        Ticket(
            username='user',
            topic='Протечка крыши в подъезде',
            description='В подъезде №3 на 5 этаже протекает крыша. Вода капает на лестничную площадку, создавая опасность для жильцов.',
            address='ул. Ленина, 15, кв. 45',
            contact_person='Иванов Иван Иванович, тел. 8-999-123-45-67',
            status=TicketStatus.NEW,
            latitude=51.2298,
            longitude=58.4755
        ),
        Ticket(
            username='user',
            topic='Не работает лифт',
            description='Лифт в подъезде №1 не работает уже 2 дня. Пожилым людям сложно подниматься по лестнице.',
            address='пр. Мира, 8, кв. 12',
            contact_person='Петрова Мария, тел. 8-999-765-43-21',
            status=TicketStatus.IN_PROGRESS,
            admin_comment='Отправлена заявка в обслуживающую компанию. Ожидаем мастера.',
            latitude=51.2287,
            longitude=58.4732
        ),
        Ticket(
            username='user',
            topic='Разбитое окно в подъезде',
            description='В подъезде разбито окно на первом этаже. Нужно срочно заменить, так как на улице холодно.',
            address='ул. Гагарина, 25, кв. 3',
            contact_person='Сидоров Алексей, тел. 8-999-555-44-33',
            status=TicketStatus.RESOLVED,
            admin_comment='Окно заменено 15.03.2024',
            latitude=51.2305,
            longitude=58.4768
        )
    ]
    
    # Добавляем заявки
    for ticket in test_tickets:
        db.session.add(ticket)
    db.session.commit()


# Декоратор для проверки авторизации пользователя
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Пожалуйста, войдите в систему.', 'warning')
            return redirect(url_for('login', next=request.url))
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Ошибка в функции {f.__name__}: {e}", exc_info=True)
            flash('Произошла внутренняя ошибка. Пожалуйста, попробуйте позже.', 'danger')
            return redirect(url_for('index'))  # или другая страница
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
    """
    Главная страница приложения.
    Отображает новости, сгруппированные по категориям.
    Поддерживает поиск по заголовкам новостей.
    """
    q = request.args.get('q', '').strip()
    query = News.query
    if q:
        query = query.filter(News.title.ilike(f'%{q}%'))
    news = query.order_by(News.date.desc()).all()
    grouped_news = {category: [] for category in CATEGORIES.values()}
    for item in news:
        if item.category in grouped_news:
            grouped_news[item.category].append(item)
        else:
            grouped_news.setdefault(item.category, []).append(item)
    return render_template('index.html',
                           grouped_news=grouped_news,
                           categories=list(CATEGORIES.values()),
                           q=q)


@app.route('/housing')
def housing():
    """
    Страница новостей категории ЖКХ.
    Отображает все новости, относящиеся к жилищно-коммунальному хозяйству.
    """
    category = CATEGORIES['housing']
    news = News.query.filter_by(category=category).all()
    return render_template('housing.html', news=news, category=category)


@app.route('/roads')
def roads():
    """
    Страница новостей категории Дороги.
    Отображает все новости, относящиеся к дорожному хозяйству.
    """
    category = CATEGORIES['roads']
    news = News.query.filter_by(category=category).all()
    return render_template('roads.html', news=news, category=category)


@app.route('/transport')
def transport():
    """
    Страница новостей категории Транспорт.
    Отображает все новости, относящиеся к транспорту.
    """
    category = CATEGORIES['transport']
    news = News.query.filter_by(category=category).all()
    return render_template('transport.html', news=news, category=category)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Страница авторизации пользователей.
    Обрабатывает вход в систему и перенаправляет на профиль при успешной авторизации.
    """
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
    """
    Выход из системы.
    Удаляет данные пользователя из сессии и перенаправляет на главную страницу.
    """
    session.pop('username', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    """
    Страница профиля пользователя.
    Отображает информацию о пользователе и его заявках.
    Требует авторизации.
    """
    username = session['username']
    user = User.query.filter_by(username=username).first()
    tickets = Ticket.query.filter_by(username=username).all()
    return render_template('profile.html', username=username, role=user.role.value, tickets=tickets)


def get_coordinates(address):
    """
    Получает географические координаты по адресу.
    Использует сервис геокодирования для преобразования адреса в координаты.
    """
    try:
        geolocator = Nominatim(user_agent="my_app")
        # Добавляем город Орск к адресу для более точного определения
        full_address = f"{address}, Орск, Оренбургская область, Россия"
        print(f"Trying to geocode address: {full_address}")  # Отладочный вывод
        location = geolocator.geocode(full_address)
        if location:
            print(f"Found coordinates: {location.latitude}, {location.longitude}")  # Отладочный вывод
            return location.latitude, location.longitude
        else:
            print("No coordinates found for address")  # Отладочный вывод
    except GeocoderTimedOut:
        print("Geocoding timed out")  # Отладочный вывод
        return None
    except Exception as e:
        print(f"Error during geocoding: {str(e)}")  # Отладочный вывод
        return None
    return None


@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    """
    Страница создания новой заявки.
    Обрабатывает создание заявки с фотографиями и геолокацией.
    Требует авторизации.
    """
    if request.method == 'POST':
        topic = request.form.get('topic', '').strip()
        description = request.form.get('description', '').strip()
        address = request.form.get('address', '').strip()
        contact_person = request.form.get('contact_person', '').strip()

        if not topic or not description:
            flash('Пожалуйста, заполните все поля.', 'warning')
            return redirect(url_for('submit_ticket'))

        coordinates = get_coordinates(address)
        if not coordinates:
            flash('Не удалось определить координаты по введённому адресу. Проверьте корректность адреса или попробуйте другой.', 'warning')
            return redirect(url_for('submit_ticket'))
        latitude, longitude = coordinates

        username = session['username']
        ticket = Ticket(
            username=username,
            topic=topic,
            description=description,
            address=address,
            contact_person=contact_person,
            latitude=latitude,
            longitude=longitude
        )
        
        if 'photos' in request.files:
            files = request.files.getlist('photos')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    photo = Photo(
                        filename=filename,
                        ticket=ticket
                    )
                    db.session.add(photo)

        db.session.add(ticket)
        db.session.commit()
        flash('Заявка успешно отправлена.', 'success')
        return redirect(url_for('submit_ticket'))

    username = session['username']
    tickets = Ticket.query.filter_by(username=username).order_by(Ticket.id.desc()).all()
    return render_template('submit_ticket.html', tickets=tickets)


@app.route('/admin')
@admin_required
def admin_panel():
    """
    Панель администратора.
    Отображает основные функции управления системой.
    Требует прав администратора.
    """
    return render_template('admin.html')


@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    """
    Страница управления заявками для администратора.
    Отображает все заявки в системе.
    Требует прав администратора.
    """
    tickets = Ticket.query.all()
    return render_template('admin_tickets.html', tickets=tickets)


@app.route('/api/search_tickets')
@admin_required
def search_tickets():
    """
    API для поиска заявок.
    Поддерживает фильтрацию по тексту и статусу.
    Требует прав администратора.
    """
    query = request.args.get('q', '').strip()
    status = request.args.get('status', '').strip()
    
    tickets_query = Ticket.query
    
    if query:
        tickets_query = tickets_query.filter(
            (Ticket.topic.ilike(f'%{query}%')) |
            (Ticket.description.ilike(f'%{query}%')) |
            (Ticket.username.ilike(f'%{query}%'))
        )
    
    if status:
        try:
            status_enum = TicketStatus(status)
            tickets_query = tickets_query.filter(Ticket.status == status_enum)
        except ValueError:
            pass
    
    tickets = tickets_query.order_by(Ticket.created_at.desc()).all()
    
    return jsonify([{
        'id': ticket.id,
        'username': ticket.username,
        'topic': ticket.topic,
        'description': ticket.description,
        'status': ticket.status.value,
        'created_at': ticket.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for ticket in tickets])


@app.route('/api/search_user_tickets')
@login_required
def search_user_tickets():
    """
    API для поиска заявок пользователя.
    Поддерживает фильтрацию по тексту и статусу.
    Требует авторизации.
    """
    query = request.args.get('q', '').strip()
    status = request.args.get('status', '').strip()
    username = session['username']
    
    tickets_query = Ticket.query.filter_by(username=username)
    
    if query:
        tickets_query = tickets_query.filter(
            (Ticket.topic.ilike(f'%{query}%')) |
            (Ticket.description.ilike(f'%{query}%'))
        )
    
    if status:
        try:
            status_enum = TicketStatus(status)
            tickets_query = tickets_query.filter(Ticket.status == status_enum)
        except ValueError:
            pass
    
    tickets = tickets_query.order_by(Ticket.created_at.desc()).all()
    
    return jsonify([{
        'id': ticket.id,
        'topic': ticket.topic,
        'description': ticket.description,
        'status': ticket.status.value,
        'created_at': ticket.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for ticket in tickets])


@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    """
    Страница просмотра заявки.
    Отображает детальную информацию о заявке и связанные фотографии.
    Требует авторизации.
    """
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.username != session['username'] and User.query.filter_by(username=session['username']).first().role != Role.ADMIN:
        abort(403)
    is_admin = User.query.filter_by(username=session['username']).first().role == Role.ADMIN
    return render_template('ticket_details.html', ticket=ticket, is_admin=is_admin)


@app.route('/api/update_ticket_status/<int:ticket_id>', methods=['POST'])
@admin_required
def update_ticket_status(ticket_id):
    """
    API для обновления статуса заявки.
    Позволяет администратору изменить статус и добавить комментарий.
    Требует прав администратора.
    """
    ticket = Ticket.query.get_or_404(ticket_id)
    new_status = request.form.get('status')
    admin_comment = request.form.get('admin_comment', '').strip()
    
    try:
        status_enum = TicketStatus(new_status)
        ticket.status = status_enum
        ticket.admin_comment = admin_comment
        db.session.commit()
        return jsonify({'success': True})
    except ValueError:
        return jsonify({'success': False, 'error': 'Неверный статус'}), 400


@app.route('/category/<category_name>')
def category_page(category_name):
    """
    Страница категории новостей.
    Отображает все новости выбранной категории.
    """
    if category_name not in CATEGORIES.values():
        abort(404)
    news = News.query.filter_by(category=category_name).all()
    return render_template('category.html', category=category_name, news=news)


@app.route('/admin/news', methods=['GET', 'POST'])
@admin_required
def admin_news():
    """
    Страница управления новостями для администратора.
    Позволяет создавать и редактировать новости.
    Требует прав администратора.
    """
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category')
        
        if not title or not content or category not in CATEGORIES.values():
            flash('Пожалуйста, заполните все поля и выберите корректный раздел.', 'warning')
            return redirect(url_for('admin_news'))
            
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = filename
        
        new_item = News(
            title=title,
            content=content,
            category=category,
            image_path=image_path
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Новость успешно добавлена.', 'success')
        return redirect(url_for('admin_news'))
        
    news = News.query.all()
    return render_template('admin_news.html', news=news, categories=list(CATEGORIES.values()))


@app.route('/help')
def help_page():
    """
    Страница помощи.
    Отображает информацию о работе с системой.
    """
    return render_template('help.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Страница регистрации новых пользователей.
    Обрабатывает создание новых учетных записей.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким логином уже существует', 'danger')
            return redirect(url_for('register'))
            
        user = User(username=username, password=password, role=Role.USER)
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация успешна! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')


def allowed_file(filename):
    """
    Проверяет, является ли расширение файла допустимым для загрузки.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/news/<int:news_id>')
def news_detail(news_id):
    """
    Страница просмотра новости.
    Отображает полное содержание новости и комментарии.
    """
    news = News.query.get_or_404(news_id)
    return render_template('news_detail.html', news=news)


@app.route('/admin/news/edit/<int:news_id>', methods=['GET', 'POST'])
@admin_required
def edit_news(news_id):
    """
    Страница редактирования новости.
    Позволяет администратору изменять содержание новости.
    Требует прав администратора.
    """
    news = News.query.get_or_404(news_id)
    if request.method == 'POST':
        news.title = request.form['title']
        news.content = request.form['content']
        news.category = request.form['category']
        
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                news.image_path = filename
        
        db.session.commit()
        flash('Новость успешно обновлена', 'success')
        return redirect(url_for('news_detail', news_id=news.id))
    
    return render_template('edit_news.html', news=news, categories=list(CATEGORIES.values()))


@app.route('/admin/news/delete/<int:news_id>', methods=['POST'])
@admin_required
def delete_news(news_id):
    """
    API для удаления новости.
    Удаляет новость и связанные с ней файлы.
    Требует прав администратора.
    """
    news = News.query.get_or_404(news_id)
    if news.image_path:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], news.image_path))
        except:
            pass
    db.session.delete(news)
    db.session.commit()
    flash('Новость успешно удалена', 'success')
    return redirect(url_for('index'))


@app.route('/news/<int:news_id>/comment', methods=['POST'])
@login_required
def add_comment(news_id):
    """
    API для добавления комментария к новости.
    Требует авторизации.
    """
    news = News.query.get_or_404(news_id)
    content = request.form.get('content', '').strip()
    
    if not content:
        flash('Комментарий не может быть пустым', 'warning')
        return redirect(url_for('news_detail', news_id=news_id))
    
    comment = Comment(
        content=content,
        username=session['username'],
        news_id=news_id
    )
    db.session.add(comment)
    db.session.commit()
    
    flash('Комментарий успешно добавлен', 'success')
    return redirect(url_for('news_detail', news_id=news_id))


@app.route('/map')
def show_map():
    """
    Страница интерактивной карты.
    Отображает заявки и объекты инфраструктуры на карте города.
    """
    m = folium.Map(location=[51.2295, 58.4751], zoom_start=13)
    
    tickets = Ticket.query.filter(Ticket.latitude.isnot(None), Ticket.longitude.isnot(None)).all()
    print(f"Found {len(tickets)} tickets with coordinates")  # Отладочный вывод
    
    for ticket in tickets:
        print(f"Adding ticket marker: {ticket.topic} at {ticket.latitude}, {ticket.longitude}")  # Отладочный вывод
        popup_text = f"""
        <b>{ticket.topic}</b><br>
        Статус: {ticket.status.value}<br>
        Адрес: {ticket.address}<br>
        <a href="/ticket/{ticket.id}">Подробнее</a>
        """
        folium.Marker(
            [ticket.latitude, ticket.longitude],
            popup=folium.Popup(popup_text, max_width=300),
            icon=folium.Icon(color='red' if ticket.status == TicketStatus.NEW else 'green')
        ).add_to(m)
    
    infrastructure = InfrastructureObject.query.all()
    print(f"Found {len(infrastructure)} infrastructure objects")  # Отладочный вывод
    
    for obj in infrastructure:
        print(f"Adding infrastructure marker: {obj.name} at {obj.latitude}, {obj.longitude}")  # Отладочный вывод
        popup_text = f"""
        <b>{obj.name}</b><br>
        Тип: {obj.type}<br>
        {obj.description}<br>
        """
        folium.Marker(
            [obj.latitude, obj.longitude],
            popup=folium.Popup(popup_text, max_width=300),
            icon=folium.Icon(color='blue', icon='info-sign')
        ).add_to(m)
    
    return render_template('map.html', map=m._repr_html_())


@app.route('/admin/infrastructure', methods=['GET', 'POST'])
@admin_required
def admin_infrastructure():
    """
    Страница управления объектами инфраструктуры.
    Позволяет администратору добавлять и редактировать объекты.
    Требует прав администратора.
    """
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        type = request.form.get('type', '').strip()
        description = request.form.get('description', '').strip()
        address = request.form.get('address', '').strip()

        if not name or not type or not address:
            flash('Пожалуйста, заполните все обязательные поля.', 'warning')
            return redirect(url_for('admin_infrastructure'))

        # Получаем координаты по адресу
        coordinates = get_coordinates(address)
        if not coordinates:
            flash('Не удалось определить координаты по указанному адресу. Проверьте правильность адреса.', 'warning')
            return redirect(url_for('admin_infrastructure'))
        
        latitude, longitude = coordinates

        infrastructure = InfrastructureObject(
            name=name,
            type=type,
            description=description,
            address=address,
            latitude=latitude,
            longitude=longitude
        )

        if 'photos' in request.files:
            files = request.files.getlist('photos')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    photo = Photo(
                        filename=filename,
                        infrastructure=infrastructure
                    )
                    db.session.add(photo)

        db.session.add(infrastructure)
        db.session.commit()
        flash('Объект инфраструктуры успешно добавлен.', 'success')
        return redirect(url_for('admin_infrastructure'))

    infrastructure = InfrastructureObject.query.all()
    return render_template('admin_infrastructure.html', infrastructure=infrastructure)


@app.route('/admin/infrastructure/delete/<int:obj_id>', methods=['POST'])
@admin_required
def delete_infrastructure(obj_id):
    """
    Удаляет объект инфраструктуры и связанные с ним фотографии.
    """
    obj = InfrastructureObject.query.get_or_404(obj_id)
    
    # Удаляем фотографии
    for photo in obj.photos:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.filename))
        except:
            pass
        db.session.delete(photo)
    
    db.session.delete(obj)
    db.session.commit()
    flash('Объект инфраструктуры успешно удален.', 'success')
    return redirect(url_for('admin_infrastructure'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
