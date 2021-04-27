from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
import psycopg2

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

engine = create_engine(
    'postgres://rettaocxxpcxlo:227f371ec68ee2c991df2f05e01f25e31005f87f3138e28b4d43a058672e5436@ec2-34-233-0-64.compute-1.amazonaws.com:5432/danc5tsjs066va', echo=False)

SessionDb = sessionmaker(bind=engine)
sessionDb = SessionDb()

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(50), unique=True)
    password = Column(String(100))


class Store(Base):
    __tablename__ = 'store'

    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    address = Column(String(300))
    category = Column(String(50))
    # user_id = db.column(db.Integer, db.ForeignKey('user.id'))


# Base.metadata.create_all(engine)

# configure Flask using environment variables
app.config.from_pyfile("config.py")


@app.route("/")
def index():
    return render_template("index.html", page_title="mitkarte")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/stores")
def stores():

    stores = sessionDb.query(Store).all()

    if stores:
        return render_template('stores.html', stores=stores)
    else:
        msg = 'No Stores Found'
        return render_template('stores.html', msg=msg)


@app.route("/store/<string:id>/")
def store(id):

    store = sessionDb.query(Store).filter(Store.id == id).first()

    return render_template("store.html", store=store)


class RegisterForm(Form):
    email = StringField(
        'Email', [validators.Email(check_deliverability=True, granular_message=True)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        if sessionDb.query(User).filter(User.email == email).count() == 0:
            data = User(email=email, password=password)
            sessionDb.add(data)
            sessionDb.commit()
            flash('You are now registered and can log in now', 'success')

            return redirect(url_for('login'))
        flash('Your email has already registered', 'danger')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        user = sessionDb.query(User).filter(User.email == email).first()

        if user:

            password = user.password

            if sha256_crypt.verify(password_candidate, password):
                # passed
                session['logged_in'] = True
                session['email'] = email

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))

            else:
                error = 'Invalid login'
            return render_template('login.html', error=error)

    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unathorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@is_logged_in
def dashboard():
    store = sessionDb.query(Store)

    if store:
        return render_template('dashboard.html', stores=store)
    else:
        msg = 'No Stores Found'
        return render_template('dashboard.html', msg=msg)

    cur.close()


class StoreForm(Form):
    name = StringField(
        'Name', [validators.Length(min=1, max=200)])
    address = TextAreaField(
        'Address', [validators.Length(min=10)])
    category = StringField(
        'Category', [validators.Length(min=1, max=30)])


@app.route('/add_store', methods=['GET', 'POST'])
@is_logged_in
def add_store():
    form = StoreForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        address = form.address.data
        category = form.category.data

        data = Store(name=name, address=address, category=category)
        sessionDb.add(data)
        sessionDb.commit()

        flash('Store added', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_store.html', form=form)


@app.route('/edit_store/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_store(id):

    post = sessionDb.query(Store).filter(Store.id == id).first()

    form = StoreForm(request.form)

    form.name.data = post.name
    form.address.data = post.address
    form.category.data = post.category

    if request.method == 'POST' and form.validate():
        name = request.form['name']
        address = request.form['address']
        category = request.form['category']

        post.name = name
        post.address = address
        post.category = category

        sessionDb.commit()

        flash('Store Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_store.html', form=form)


@app.route('/delete_store/<string:id>', methods=['POST'])
@is_logged_in
def delete_store(id):

    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM stores WHERE id = %s", [id])

    mysql.connection.commit()

    cur.close()

    flash('Store Deleted', 'success')

    return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.secret_key = 'secret123'
    app.run(host="localhost", port=8080, debug=True)
