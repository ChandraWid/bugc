from flask import Flask, render_template, redirect, url_for, request, flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Email, Length, Optional
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Default XAMPP MySQL user
app.config['MYSQL_PASSWORD'] = ''  # Default XAMPP MySQL password
app.config['MYSQL_DB'] = 'bucky'

mysql = MySQL(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(id=user[0], username=user[1], email=user[2], role=user[4])
    return None

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=150)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=150)])
    submit = SubmitField('Login')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[Length(min=4, max=150)])
    poin = IntegerField('Poin', validators=[InputRequired()])
    submit = SubmitField('Save')

class EditForm(FlaskForm):
    username = StringField('Username', validators=[Optional(), Length(min=4, max=150)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[Optional(), Length(min=4, max=150)])
    poin = IntegerField('Poin', validators=[Optional()])
    submit = SubmitField('Save')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                    (form.username.data, form.email.data, hashed_password, 'user'))
        mysql.connection.commit()
        cur.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (form.email.data,))
        user = cur.fetchone()
        cur.close()
        if user and check_password_hash(user[3], form.password.data):
            user_obj = User(id=user[0], username=user[1], email=user[2], role=user[4])
            login_user(user_obj)
            if user[4] == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('landing'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/landing')
@login_required
def landing():
    cur = mysql.connection.cursor()
    cur.execute("SELECT poin FROM users WHERE id = %s", (current_user.id,))
    user_points = cur.fetchone()
    cur.close()
    
    if user_points:
        user_points = user_points[0]
    else:
        user_points = 0
    
    return render_template('landing.html', user_points=user_points)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))

    cur = mysql.connection.cursor()

    # Fetch total users
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    # Fetch total transactions
    cur.execute("SELECT COUNT(*) FROM transaction")
    total_transactions = cur.fetchone()[0]

    # Fetch transaction data for the chart
    cur.execute("SELECT DATE(transaction_time) as date, COUNT(*) as count FROM transaction GROUP BY date")
    transactions = cur.fetchall()
    cur.close()

    # Format transactions data for JavaScript
    transactions_data = {str(row[0]): row[1] for row in transactions}

    return render_template('dashboard.html', total_users=total_users, total_transactions=total_transactions, transactions=transactions_data)


@app.route('/user')
@login_required
def user():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, email, poin FROM users")
    users = cur.fetchall()
    cur.close()

    return render_template('user.html', users=users)

@app.route('/user/create', methods=['GET', 'POST'])
@login_required
def user_create():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    
    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password, poin, role) VALUES (%s, %s, %s, %s, %s)",
                    (form.username.data, form.email.data, hashed_password, form.poin.data, 'user'))
        mysql.connection.commit()
        cur.close()
        flash('User created successfully!', 'success')
        return redirect(url_for('user'))
    return render_template('user_form.html', form=form, action='Create')

@app.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('landing'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, email, poin FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user'))

    form = EditForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        updates = []
        values = []

        if form.username.data and form.username.data != user[1]:
            updates.append("username = %s")
            values.append(form.username.data)
        if form.email.data and form.email.data != user[2]:
            updates.append("email = %s")
            values.append(form.email.data)
        if form.password.data:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            updates.append("password = %s")
            values.append(hashed_password)
        if form.poin.data is not None and form.poin.data != user[3]:  # Handle 0 and None differently
            updates.append("poin = %s")
            values.append(form.poin.data)

        if updates:
            values.append(user_id)
            update_query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
            cur = mysql.connection.cursor()
            cur.execute(update_query, tuple(values))
            mysql.connection.commit()
            cur.close()
            flash('User updated successfully!', 'success')
        else:
            flash('No changes detected.', 'info')
        
        return redirect(url_for('user'))

    # Prefill the form with existing user data
    form.username.data = user[1]
    form.email.data = user[2]
    form.poin.data = user[3]

    return render_template('user_form.html', form=form, action='Edit')

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def user_delete(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('landing'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('user'))

@app.route('/transaksi')
@login_required
def transaksi():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, id_user, username, jenis, reward, transaction_time FROM transaction")
    transactions = cur.fetchall()
    cur.close()

    return render_template('transaksi.html', transactions=transactions)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
