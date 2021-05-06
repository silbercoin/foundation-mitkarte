from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
import psycopg2
import os
import folium
import geocoder
from os import environ

from flask_login import current_user

from sqlalchemy import create_engine, Table, Column, Integer, String, ForeignKey, func, DateTime, update
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy.ext.declarative import declarative_base

from wtforms import Form, StringField, IntegerField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

app.config.from_object('config.ProdConfig')

engine = create_engine(app.config["DATABASE_URI"])
SessionDb = sessionmaker(bind=engine)
sessionDb = SessionDb()
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    userId = Column(Integer, primary_key=True)
    userEmail = Column(String(50), unique=True)
    userPassword = Column(String(100))

    posts = relationship('Store', backref='poster', lazy='dynamic')


class Store(Base):
    __tablename__ = 'store'

    storeId = Column(Integer, primary_key=True)
    storeName = Column(String(50), nullable=False)
    storeAddress = Column(String(100), unique=True, nullable=False)
    storeZipcode = Column(Integer)
    storeCity = Column(String(10), default='Berlin')
    storeLat = Column(String(20))
    storeLon = Column(String(20))
    storeCategory = Column(String(50), nullable=False)
    posttime = Column(DateTime(timezone=True), server_default=func.now())
    posterId = Column(Integer, ForeignKey('user.userId'))
    note = Column(String(255))


Base.metadata.create_all(engine)


# configure Flask using environment variables
app.config.from_pyfile("config.py")


@app.route("/")
def index():
    return render_template("index.html", page_title="mitkarte")


@app.route("/about")
def about():
    coord = sessionDb.query(Store).all()
    map = folium.Map(location=[52.520008, 13.404954],
                     zoom_start=12, height='100%', width='100%', tiles=app.config["MAPBOX_API"], attr='mapbox')

    for store in coord:
        folium.Marker([store.storeLat, store.storeLon],
                      popup=store.storeName, tooltip=store.storeCategory, icon=folium.Icon(color='red', icon='credit-card')).add_to(map)

    return render_template("about.html", map=map._repr_html_())


@app.route("/stores")
def stores():

    bar = sessionDb.query(Store).filter(
        Store.storeCategory == 'Bar').all()
    backery = sessionDb.query(Store).filter(
        Store.storeCategory == 'Backery').all()
    coffee = sessionDb.query(Store).filter(
        Store.storeCategory == 'Coffee Shop').all()
    ice = sessionDb.query(Store).filter(
        Store.storeCategory == 'Icecream shop').all()
    restuarant = sessionDb.query(Store).filter(
        Store.storeCategory == 'Restuarant').all()
    spati = sessionDb.query(Store).filter(
        Store.storeCategory == 'Späti').all()

    return render_template('stores.html', bar=bar, backery=backery, coffee=coffee, ice=ice, restuarant=restuarant, spati=spati)


@app.route("/store/<string:id>/")
def store(id):

    store = sessionDb.query(Store).filter(
        Store.storeId == id).first()

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

        if sessionDb.query(User).filter(User.userEmail == email).count() == 0:
            data = User(userEmail=email, userPassword=password)
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

        user = sessionDb.query(User).filter(User.userEmail == email).first()

        if user:

            password = user.userPassword

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
    user = sessionDb.query(User).filter_by(
        userEmail=session['email']).first()

    store = sessionDb.query(Store).filter_by(posterId=user.userId)

    if store:
        return render_template('dashboard.html', stores=store)
    else:
        msg = 'No Stores Found'
        return render_template('dashboard.html', msg=msg)


class StoreForm(Form):
    storeName = StringField(
        'Store Name', [validators.InputRequired()])
    storeAddress = StringField(
        'Address', [validators.InputRequired()])
    Zipcode = IntegerField('Zip Code', [validators.NumberRange(
        min=10115, max=14169, message='Berlin zip code is between 10115 to 14169')])
    City = StringField('City', default='Berlin')

    storeCategory = SelectField('Category', [validators.InputRequired()], choices=[('Store', 'Store'), ('Backery', 'Backery'), ('Coffee Shop', 'Coffee Shop'), (
        'Icecream shop', 'Icecream shop'), ('Restuarant', 'Restuarant'), ('Florist', 'Florist'), ('Pharmacy', 'Pharmacy'), ('Bar', 'Bar'), ('Hair shop', 'Hair shop'), ('Public Bathroom', 'Public Bathroom'), ('Späti', 'Späti')])
    note = StringField('Note')


@ app.route('/add_store', methods=['GET', 'POST'])
@ is_logged_in
def add_store():
    form = StoreForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.storeName.data
        address = form.storeAddress.data
        zipcode = form.Zipcode.data
        city = form.City.data
        category = form.storeCategory.data
        note = form.note.data

        if sessionDb.query(Store).filter(Store.storeAddress == address).count() == 0:

            user = sessionDb.query(User).filter(
                User.userEmail == session['email']).first()

            g = geocoder.mapbox(f'{address},{zipcode}{city},Germany',
                                key=app.config["MAPBOX_KEY"])

            data = Store(storeName=name, storeAddress=address, storeZipcode=zipcode,
                         storeCity=city, storeCategory=category, storeLat=g.lat, storeLon=g.lng, note=note, poster=user)
            sessionDb.add(data)
            sessionDb.commit()

            flash('Store added', 'success')
            return redirect(url_for('dashboard'))

        else:

            sessionDb.rollback()

            flash('store address is already in the database', 'warning')

            return redirect(url_for('dashboard'))

    return render_template('add_store.html', form=form)


@ app.route('/edit_store/<string:id>', methods=['GET', 'POST'])
@ is_logged_in
def edit_store(id):

    edit = sessionDb.query(Store).filter(Store.storeId == id).first()

    form = StoreForm(request.form)

    form.storeCategory.data = edit.storeCategory

    if request.method == 'POST' and form.validate():

        edit.storeName = request.form['storeName']
        edit.storeAddress = request.form['storeAddress']
        edit.storeZipcode = request.form['Zipcode']
        edit.storeCategory = request.form['storeCategory']
        edit.note = request.form['note']

        try:
            sessionDb.commit()
            flash('Store edited', 'success')

            return redirect(url_for('dashboard'))

        except:
            sessionDb.rollback()
            flash('cannot edit the store', 'warning')
            return redirect(url_for('dashboard'))

    return render_template('edit_store.html', form=form, edit=edit)


@ app.route('/delete_store/<string:id>', methods=['POST'])
@ is_logged_in
def delete_store(id):

    post = sessionDb.query(Store).filter(Store.storeId == id).first()
    sessionDb.delete(post)
    sessionDb.commit()

    flash('Store Deleted', 'success')

    return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.secret_key = app.config["SECRET_KEY"]
    port = os.environ.get("PORT", 5000)
    app.run(host="0.0.0.0", port=port)
