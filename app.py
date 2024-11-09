from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length
import json
import requests
import plotly.graph_objs as go
import plotly
import pandas as pd

app = Flask(__name__)
app.config['SECRET_KEY'] = 'This-is-my-very-secret-key'

# Создание и подключение базы данных sqlite

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Clients(UserMixin, db.Model):  # Создание класса базы данных, описание полей
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader  # Определение авторизованного пользователя
def load_user(user_id):
    return Clients.query.get(int(user_id))


class LoginForm(FlaskForm):  # Создание класса формы авторизации пользователя, описание полей формы
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("Запомнить меня", default=False)


class RegisterForm(FlaskForm):  # Создание класса формы регистрации пользователя, описание полей формы
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')  # создание url для главной страницы
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])  # url для страницы авторизации
def login():
    form = LoginForm()  # использование wtform

#  Проверка, существует ли пользователь с логином, введенным в форму авторизации
    if form.validate_on_submit():
        client = Clients.query.filter_by(login=form.username.data).first()
        if client:
            if check_password_hash(client.password, form.password.data):  # Введенный пароль хэшируется и сверяется
                # с хэшем пароля пользователя из базы данных
                login_user(client, remember=form.remember.data)
                resp = make_response(redirect(url_for('moex_api')))
                resp.set_cookie('username', form.username.data)  # Создание куки
                return resp
            else:
                flash('Неверный логин или пароль!', category='error')
        else:
            flash('Неверный логин или пароль!', category='error')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])  # url для страницы регистрации пользователя
def register():
    form = RegisterForm()  # использование wtform

    if form.validate_on_submit():
        if Clients.query.filter_by(login=form.username.data).first():  # проверка на наличие уже существующего
            # пользователя с таким логином
            flash('Пользователь с таким логином уже существует!', category='error')
        else:
            hash_password = generate_password_hash(form.password.data)  # 'хэширование пароля
            new_client = Clients(login=form.username.data, password=hash_password)  # создание нового клиента и запись
            # в базу данных
            try:
                db.session.add(new_client)
                db.session.commit()
                flash('Вы успешно зарегистрировались!', category='success')
                return redirect(url_for('login'))
            except:
                flash('Что-то пошло не так!', category='error')

    return render_template('register.html', form=form)


@app.route('/moex_api', methods=['POST', 'GET'])  # url страницы, на которой выгружаются данные через API
# Московской биржи
@login_required  # Для входа необходима авторизация
def moex_api():
    username = request.cookies.get('username')  # Запрос куки
    if username:
        return render_template('moex_api.html', username=username, name=current_user.login)
    return render_template('moex_api.html', name=current_user.login)


@app.route('/logout')  # Завершение сеанса
@login_required
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('username')  # Удаление куки
    logout_user()
    return resp


@app.route('/about')  # url для страницы, отображающей информацию об агентстве
def about():
    return render_template('about.html')


@app.route('/contacts')  # url для страницы с контактами информационного агентства
def contacts():
    return render_template('contacts.html')


@app.route('/submit', methods=['POST'])
def submit():

    '''Запрос к ИСС Московской биржи и его обработка'''

    securityType = request.form.get('securityType')  # Запрос данных из формы со страницы /moex_api
    stock_symbol = request.form.get('stock_symbol')
    firstDate = request.form.get('firstDate')
    lastDate = request.form.get('lastDate')

    if securityType == 'TQBR':
        sec_type = 'shares'
    else:
        sec_type = 'bonds'

    response = requests.get(f'https://iss.moex.com/iss/history/engines/stock/markets/{sec_type}/boards/'
                            f'{securityType}/securities/{stock_symbol}.json?from='
                            f'{firstDate}&till={lastDate}&iss.meta=off&iss.only=history&'
                            f'history.columns=TRADEDATE,SHORTNAME,CLOSE,VOLUME')

    if response.status_code == 200:
        result = json.loads(response.text)
        resp_data = result['history']['data']
        data_securities = pd.DataFrame(resp_data)
        a = len(resp_data)

        b = 100
        while a == 100:
            url_next_page = (f'https://iss.moex.com/iss/history/engines/stock/markets/{sec_type}/boards/'
                             f'{securityType}/securities/{stock_symbol}.json?from={firstDate}&till={lastDate}'
                             f'&iss.meta=off&iss.only=history&history.columns=TRADEDATE,SHORTNAME,CLOSE,VOLUME&start={b}')
            new_response = requests.get(url_next_page)
            new_result = json.loads(new_response.text)
            resp_data = new_result['history']['data']
            data_next_page = pd.DataFrame(resp_data)
            data_securities = pd.concat([data_securities, data_next_page], ignore_index=True)
            a = len(resp_data)
            b = b + 100

        security_name = data_securities[1][1]
        dates = data_securities[0]
        prices = data_securities[2]

        # Создание графика изменения цен финансового актива
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=dates, y=prices, mode='lines'))
        fig.update_layout(title=f'{security_name}')

        graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

        return jsonify(graph_json=graph_json)

    else:
        return redirect(url_for('500'))


@app.route('/500')  # ошибка 500
def internal():
    abort(500)


if __name__ == '__app__':
    app.run(debug=True)
