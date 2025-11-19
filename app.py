from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify 
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime, timedelta
from functools import wraps

# --- CẤU HÌNH QUAN TRỌNG ---
# template_folder='.' giúp Flask tìm thấy các file html ngay tại thư mục hiện tại
app = Flask(__name__, template_folder='.')

app.config['SECRET_KEY'] = 'chia_khoa_bi_mat_123456'
DATABASE_NAME = 'app_data.db'
ADMIN_USERNAME = 'thiennhan'
ADMIN_PASS_HASH = generate_password_hash('admin') 

# --- Database & Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT UNIQUE, password_hash TEXT, expiry_date TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS tools (id INTEGER PRIMARY KEY, name TEXT, tool_code TEXT UNIQUE)''')
        cursor = conn.execute("SELECT * FROM users WHERE name = ?", (ADMIN_USERNAME,))
        if cursor.fetchone() is None:
            conn.execute("INSERT INTO users (name, password_hash, expiry_date) VALUES (?, ?, ?)", (ADMIN_USERNAME, ADMIN_PASS_HASH, '9999-12-31 23:59:59'))

def get_user_by_name(name):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_tool_by_code(code):
    conn = get_db_connection()
    tool = conn.execute("SELECT * FROM tools WHERE tool_code = ?", (code,)).fetchone()
    conn.close()
    return dict(tool) if tool else None

# --- Decorators ---
def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth or not auth.startswith('Bearer '):
            return jsonify({"message": "Missing Authorization header"}), 401
        code = auth.split(' ')[1]
        tool = get_tool_by_code(code)
        if not tool:
            return jsonify({"message": "Invalid Tool Code"}), 401
        request.tool_info = tool
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in_as' not in session: 
            # Chuyển hướng về trang đăng nhập nếu chưa login
            return redirect(url_for('login', message='Bạn cần đăng nhập để truy cập trang này.'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin': abort(403)
        return f(*args, **kwargs)
    return decorated

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def login():
    msg = request.args.get('message', "")
    if request.method == "POST":
        role = request.form.get("role")
        
        if role in ["admin", "user"]:
            name = request.form.get("username")
            pwd = request.form.get("password")
            user = get_user_by_name(name)
            if user and check_password_hash(user['password_hash'], pwd):
                session['logged_in_as'] = name
                session['role'] = 'admin' if name == ADMIN_USERNAME else 'user'
                return redirect(url_for('admin_page' if session['role'] == 'admin' else 'user_page', username=name))
            msg = "Sai thông tin đăng nhập"
            
        elif role == "tool":
            code = request.form.get("tool_code")
            tool = get_tool_by_code(code)
            if tool:
                session['logged_in_as'] = f"tool_{code}"
                session['role'] = 'tool'
                return redirect(url_for('tool_page', tool_code=code))
            msg = "Sai mã tool"
            
    # RENDER TỚI LOGIN.HTML
    return render_template("login.html", message=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_page():
    conn = get_db_connection()
    if request.method == "POST":
        if "add_user" in request.form:
            try:
                pwd = generate_password_hash(request.form.get("user_pass"))
                exp = (datetime.now() + timedelta(days=int(request.form.get("user_time")))).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute("INSERT INTO users (name, password_hash, expiry_date) VALUES (?,?,?)", (request.form.get("user_name"), pwd, exp))
                conn.commit()
            except sqlite3.IntegrityError:
                pass 
        if "add_tool" in request.form:
            try:
                conn.execute("INSERT INTO tools (name, tool_code) VALUES (?,?)", (request.form.get("tool_user"), request.form.get("tool_code")))
                conn.commit()
            except sqlite3.IntegrityError:
                pass 
        if "delete_user" in request.form and request.form.get("delete_user_name") != ADMIN_USERNAME:
            conn.execute("DELETE FROM users WHERE name=?", (request.form.get("delete_user_name"),))
            conn.commit()
        if "delete_tool" in request.form:
            conn.execute("DELETE FROM tools WHERE tool_code=?", (request.form.get("delete_tool_code"),))
            conn.commit()
            
    users = conn.execute("SELECT * FROM users ORDER BY name").fetchall()
    tools = conn.execute("SELECT * FROM tools ORDER BY name").fetchall()
    conn.close()
    # RENDER TỚI ADMIN.HTML
    return render_template("admin.html", users=users, tools=tools)

@app.route("/user/<username>")
@login_required
def user_page(username):
    user = get_user_by_name(username)
    # RENDER TỚI USER.HTML
    return render_template("user.html", user=user)

@app.route("/tool/<tool_code>")
@login_required
def tool_page(tool_code):
    tool = get_tool_by_code(tool_code)
    # RENDER TỚI TOOL_VIEW.HTML
    return render_template("tool_view.html", tool=tool)

@app.route('/api/v1/tool/status')
@api_key_required
def api_status():
    tool_info = request.tool_info
    return jsonify({
        "status": "active", 
        "tool_name": tool_info['name'],
        "message": "Tool OK"
    }), 200

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=80, debug=True)