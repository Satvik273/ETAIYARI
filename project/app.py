from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
import datetime
import os



ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'docx'}

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    exam = db.Column(db.String(100))
    postal_code = db.Column(db.String(20))
    phone = db.Column(db.String(20))
    gender = db.Column(db.String(10))

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    filepath = db.Column(db.String(200))
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))




@app.route('/')
def home():
    # Example: Load user from session
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('home.html', user=user)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        postal_code = request.form['postal_code']
        phone = request.form['phone']
        exam = request.form['exam']
        gender = request.form['gender']

        # Check if user exists
        if User.query.filter_by(username=username).first():
            return "Username already taken"
        if User.query.filter_by(email=email).first():
            return "Email already registered"

        # Create and save new user
        new_user = User(name=name, username=username, email=email,
                        password=password, postal_code=postal_code,
                        phone=phone, exam=exam, gender=gender)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        return "Invalid credentials"
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            new_file = File(filename=filename, filepath=filepath, user_id=session['user_id'])
            db.session.add(new_file)
            db.session.commit()

            return render_template('upload.html', user=user, message="File uploaded successfully!")
        else:
            return render_template('upload.html', user=user, message="Invalid file type")
    return render_template('upload.html', user=user, message=None)

@app.route('/update', methods=['GET', 'POST'])
def update():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    message = None
    if request.method == 'POST':
        user.name = request.form['name']
        user.username = request.form['username']
        user.email = request.form['email']
        user.postal_code = request.form['postal_code']
        user.phone = request.form['phone']
        user.exam = request.form['exam']
        user.gender = request.form['gender']
        password = request.form['password']
        if password:
            user.password = generate_password_hash(password)
        db.session.commit()
        message = "Details updated successfully!"
    return render_template('update.html', user=user, message=message)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
