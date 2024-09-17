import os
from http import HTTPStatus
from typing import Dict, Optional

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.wrappers import Response as WerkzeugResponse
from flask_caching import Cache
import hashlib

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '1q2w3e4r5t')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
api_url = 'https://cloud-api.yandex.net/v1/disk/public/resources'
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# utils # # #


def is_valid_url(url: str) -> bool:
    """Вадилация сслыки на запрашиваемый ресурс Яндекс Диска."""
    import re
    url_pattern = re.compile(r'^(https?://)[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    return re.match(url_pattern, url) is not None


def make_cache_key():
    """Создаём уникальный ключ для кэша на основе данных POST-запроса."""
    data = request.get_data()
    return hashlib.md5(data).hexdigest()


# тестовый пользователь и авторизация # # #


class User(UserMixin):
    def __init__(self, id: int, username: str, password: str):
        self.id = id
        self.username = username
        self.password = password


user = User(1, 'admin', 'admin')


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Загрузка пользователя из хранилища по ID."""
    if user.id == int(user_id):
        return user
    return None


@app.route('/login', methods=('GET', 'POST'))
def login() -> Response | WerkzeugResponse:
    if request.method == 'POST':
        username: str = request.form['username']
        password: str = request.form['password']
        if user.username == username and user.password == password:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Неправильное имя пользователя и/или пароль.')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout() -> WerkzeugResponse:
    logout_user()
    flash('Вы вышли из учётной записи.')
    return redirect(url_for('login'))


# эндпоинты # # #


@app.route('/', methods=('GET', 'POST'))
@login_required
@cache.cached(timeout=60, key_prefix=make_cache_key)
def home() -> Response | str:
    """Получение списка папок и файлов по запросу."""
    if request.method == 'POST':
        data: Dict[str, str] = request.json
        url = data.get('url', '')
        if not is_valid_url(url):
            return jsonify({'error': 'Некорректный URL.'}), HTTPStatus.BAD_REQUEST
        global api_url
        fields = (
            '_embedded.items.name, \
            _embedded.items.type, \
            _embedded.items.sizes, \
            _embedded.items.path,'
        )
        response = requests.get(api_url, params={'public_key': url, 'fields': fields})
        return response.json()
    return render_template('index.html')


@app.route('/download', methods=['POST'])
@login_required
def download() -> Response:
    """Загрузка файла или папки с ресурса."""
    data: Dict[str, str] = request.json
    url = data.get('url', '')
    path = data.get('path', '')
    global api_url
    response = requests.get(api_url + '/download', params={'public_key': url, 'path': path})
    return response.json()


if __name__ == '__main__':
    app.run(debug=True)
