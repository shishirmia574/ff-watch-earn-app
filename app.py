from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey123'
DB = 'database.db'

# Initialize the database
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            coins INTEGER DEFAULT 0,
            ref_by TEXT,
            ip TEXT,
            verify_code TEXT,
            is_subscribed INTEGER DEFAULT 0,
            subscription_expires TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            filename TEXT,
            owner TEXT,
            approved INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS views (
            user TEXT,
            video_id INTEGER,
            timestamp TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS redeems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            coins_used INTEGER,
            status TEXT,
            date TEXT
        )''')

init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@login_required
def index():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM videos WHERE approved=1")
        videos = c.fetchall()
    return render_template('index.html', videos=videos, user=session['user'])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        ref = request.form.get('ref')
        ip = request.remote_addr
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username, password, email, ref_by, ip) VALUES (?, ?, ?, ?, ?)",
                          (uname, pwd, email, ref, ip))
                if ref:
                    c.execute("UPDATE users SET coins = coins + 100 WHERE username=?", (ref,))
            except sqlite3.IntegrityError:
                flash("Username already exists")
                return redirect(url_for('signup'))
            conn.commit()
        session['user'] = uname
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (uname, pwd))
            user = c.fetchone()
        if user:
            session['user'] = uname
            return redirect(url_for('index'))
        else:
            flash("Invalid login")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=?", (email,))
            user = c.fetchone()
            if user:
                flash("Password reset link sent to your email (not implemented).")
            else:
                flash("If the email exists, reset instructions have been sent.")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/wallet', methods=['GET', 'POST'])
@login_required
def wallet():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT coins, is_subscribed, subscription_expires FROM users WHERE username=?", (session['user'],))
        result = c.fetchone()
        coins, subscribed, sub_exp = result

        if request.method == 'POST':
            code = request.form['code']
            if code == 'Black@1':
                new_expiry = (datetime.now() + timedelta(days=30)).isoformat()
                c.execute("UPDATE users SET is_subscribed=1, subscription_expires=? WHERE username=?", (new_expiry, session['user']))
                flash("✅ Subscription activated for 30 days.")
                return redirect(url_for('wallet'))
            else:
                flash("❌ Invalid subscription code.")

    return render_template('wallet.html', coins=coins, subscribed=subscribed, sub_exp=sub_exp, now=datetime.now().isoformat())

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT is_subscribed, subscription_expires FROM users WHERE username=?", (session['user'],))
        result = c.fetchone()
        subscribed, expires = result
        now = datetime.now()
        if not subscribed or (expires and datetime.fromisoformat(expires) < now):
            flash("You need to subscribe or renew subscription to upload videos.")
            return redirect(url_for('wallet'))

    if request.method == 'POST':
        f = request.files['video']
        title = request.form['title']
        fname = f.filename
        save_path = os.path.join('static', fname)
        f.save(save_path)
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO videos (title, filename, owner) VALUES (?, ?, ?)",
                      (title, fname, session['user']))
        flash("Video uploaded, pending admin approval.")
        return redirect(url_for('upload'))
    return render_template('upload.html')

@app.route('/watch/<int:vid>')
@login_required
def watch(vid):
    uname = session['user']
    now = datetime.now().isoformat()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM views WHERE user=? AND video_id=?", (uname, vid))
        already = c.fetchone()
        if not already:
            c.execute("INSERT INTO views (user, video_id, timestamp) VALUES (?, ?, ?)", (uname, vid, now))
            c.execute("SELECT owner FROM videos WHERE id=?", (vid,))
            owner = c.fetchone()[0]
            if owner == 'admin':
                c.execute("UPDATE users SET coins = coins + 50 WHERE username=?", (uname,))
            else:
                c.execute("UPDATE users SET coins = coins + 25 WHERE username=?", (owner,))
        c.execute("SELECT filename, title FROM videos WHERE id=?", (vid,))
        video = c.fetchone()
    if not video:
        flash("Video not found or not approved.")
        return redirect(url_for('index'))
    return render_template('watch.html', video=video)

@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    if request.method == 'POST':
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT coins FROM users WHERE username=?", (session['user'],))
            coins = c.fetchone()[0]
            if coins >= 1000:
                coins_used = int(request.form.get('coins_to_use', '1000'))
                if coins_used > coins:
                    flash("You don't have enough coins.")
                    return redirect(url_for('redeem'))
                c.execute("INSERT INTO redeems (username, coins_used, status, date) VALUES (?, ?, ?, ?)",
                          (session['user'], coins_used, 'pending', datetime.now().isoformat()))
                c.execute("UPDATE users SET coins = coins - ? WHERE username=?", (coins_used, session['user']))
                flash("Redeem requested successfully!")
                return redirect(url_for('redeem'))
            else:
                flash("You need at least 1000 coins to redeem.")
                return redirect(url_for('redeem'))
    return render_template('redeem.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        if user == 'Shishir' and pwd == '1710430542':
            session['admin'] = True
        else:
            flash("Unauthorized access")
            return redirect(url_for('admin'))
    if 'admin' not in session:
        return render_template('admin_login.html')
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM redeems")
        redeems = c.fetchall()
        c.execute("SELECT * FROM videos WHERE approved=0")
        videos = c.fetchall()
        c.execute("SELECT owner, COUNT(*) FROM videos GROUP BY owner")
        earnings = c.fetchall()
    return render_template('admin.html', redeems=redeems, videos=videos, earnings=earnings)

@app.route('/approve/<int:vid>')
def approve(vid):
    if 'admin' not in session:
        flash("Login as admin first.")
        return redirect(url_for('admin'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("UPDATE videos SET approved=1 WHERE id=?", (vid,))
    flash("Video approved.")
    return redirect(url_for('admin'))

@app.route('/reject/<int:vid>')
def reject(vid):
    if 'admin' not in session:
        flash("Login as admin first.")
        return redirect(url_for('admin'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM videos WHERE id=?", (vid,))
    flash("Video rejected and deleted.")
    return redirect(url_for('admin'))

@app.route('/delete/<int:vid>')
@login_required
def delete(vid):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT owner FROM videos WHERE id=?", (vid,))
        result = c.fetchone()
        if result and result[0] == session['user']:
            c.execute("DELETE FROM videos WHERE id=?", (vid,))
            flash("Your video has been deleted.")
        else:
            flash("Unauthorized or video not found.")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
