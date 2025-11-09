
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3, os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB = 'database.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_column(conn, table, column_def):
    col_name = column_def.split()[0]
    cur = conn.cursor()
    try:
        cur.execute(f"PRAGMA table_info({table})")
        cols = [r[1] for r in cur.fetchall()]
        if col_name not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
            conn.commit()
    except Exception as e:
        print('ensure_column error:', e)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0)')
    c.execute('CREATE TABLE IF NOT EXISTS menu (id INTEGER PRIMARY KEY AUTOINCREMENT, day TEXT, meal_type TEXT, item TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, meal_type TEXT, rating INTEGER, comment TEXT, created_at TEXT)')
    conn.commit()
    ensure_column(conn, 'feedback', 'user_id INTEGER')
    ensure_column(conn, 'feedback', 'name TEXT')
    ensure_column(conn, 'feedback', 'meal_type TEXT')
    ensure_column(conn, 'feedback', 'rating INTEGER')
    ensure_column(conn, 'feedback', 'comment TEXT')
    ensure_column(conn, 'feedback', 'created_at TEXT')

    admin_user = os.environ.get('MESS_ADMIN_USER', 'messmaster')
    admin_pass = os.environ.get('MESS_ADMIN_PASS', 'renovate')

    c.execute('SELECT id, password FROM users WHERE username=?', (admin_user,))
    row = c.fetchone()
    if row:
        stored = row[1] or ''
        if not (stored.startswith('pbkdf2:') or stored.startswith('sha256:')):
            c.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(admin_pass), row[0]))
    else:
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)', (admin_user, generate_password_hash(admin_pass)))
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/')
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM menu ORDER BY id')
    menu = c.fetchall()
    c.execute('SELECT meal_type, AVG(rating) as avg_rating, COUNT(*) as cnt FROM feedback GROUP BY meal_type')
    ratings = { row['meal_type']: {'avg': round(row['avg_rating'],1) if row['avg_rating'] is not None else 0, 'count': row['cnt']} for row in c.fetchall() }
    conn.close()
    return render_template('index.html', menu=menu, ratings=ratings)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required.', 'danger')
            return redirect(url_for('register'))
        conn = get_db(); c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username,password) VALUES (?,?)', (username, generate_password_hash(password)))
            conn.commit()
            flash('Registered successfully. Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Username already taken.', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db(); c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/feedback', methods=['GET','POST'])
@login_required
def feedback():
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            user_id = session.get('user_id')
            name = data.get('name') or session.get('username') or ''
            meal_type = data.get('meal_type')
            rating = int(data.get('rating') or 0)
            comment = data.get('comment','').strip()
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = get_db(); c = conn.cursor()
            c.execute('INSERT INTO feedback (user_id,name,meal_type,rating,comment,created_at) VALUES (?,?,?,?,?,?)', (user_id,name,meal_type,rating,comment,created_at))
            conn.commit(); conn.close()
            if request.is_json:
                return jsonify({'status':'success'})
            flash('Thank you for your feedback!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            print('Feedback submission error:', e)
            if request.is_json:
                return jsonify({'status':'error','message':str(e)}), 400
            flash('Failed to submit feedback: '+str(e), 'danger')
            return redirect(url_for('feedback'))
    return render_template('feedback.html')

@app.route('/admin')
@admin_required
def admin():
    conn = get_db(); c = conn.cursor()
    c.execute('SELECT f.*, u.username FROM feedback f LEFT JOIN users u ON f.user_id=u.id ORDER BY f.created_at DESC')
    feedbacks = c.fetchall()
    c.execute('SELECT * FROM menu ORDER BY id')
    menu = c.fetchall()
    conn.close()
    return render_template('admin.html', feedbacks=feedbacks, menu=menu)

@app.route('/menu/add', methods=['POST'])
@admin_required
def add_menu_item():
    day = request.form.get('day','').strip()
    meal_type = request.form.get('meal_type','').strip()
    item = request.form.get('item','').strip()
    conn = get_db(); c = conn.cursor()
    c.execute('INSERT INTO menu (day,meal_type,item) VALUES (?,?,?)', (day,meal_type,item))
    conn.commit(); conn.close()
    flash('Menu item added.', 'success')
    return redirect(url_for('admin'))

@app.route('/menu/delete/<int:id>', methods=['POST'])
@admin_required
def delete_menu_item(id):
    conn = get_db(); c = conn.cursor()
    c.execute('DELETE FROM menu WHERE id=?', (id,))
    conn.commit(); conn.close()
    flash('Menu item removed.', 'info')
    return redirect(url_for('admin'))

@app.route('/menu/update/<int:id>', methods=['POST'])
@admin_required
def update_menu_item(id):
    item = request.form.get('item','').strip()
    conn = get_db(); c = conn.cursor()
    c.execute('UPDATE menu SET item=? WHERE id=?', (item,id))
    conn.commit(); conn.close()
    flash('Menu item updated.', 'success')
    return redirect(url_for('admin'))

@app.route('/feedback/delete/<int:id>', methods=['POST'])
@admin_required
def delete_feedback(id):
    conn = get_db(); c = conn.cursor()
    c.execute('DELETE FROM feedback WHERE id=?', (id,))
    conn.commit(); conn.close()
    flash('Feedback deleted.', 'info')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
