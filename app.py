from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
import os
import json

app = Flask(__name__)

# 从文件中读取密钥
SECRET_KEY_FILE = 'SECRETKEY'
with open(SECRET_KEY_FILE, 'r') as f:
    app.secret_key = f.read().strip()

# 文件存储路径
USER_DATA_FILE = 'user_data.json'

# 上传文件保存的目录
UPLOAD_FOLDER = '/upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 检查用户权限
def check_permission(username, file_path):
    with open(USER_DATA_FILE, 'r') as f:
        user_data = json.load(f)
    if username in user_data:
        permissions = user_data[username].get('permissions', [])
        for path, access in permissions.items():
            if file_path.startswith(path) and access == 'read':
                return True
    return False

# 读取文件内容
def read_file(file_path, username):
    if check_permission(username, file_path):
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return 'File not found.'
    else:
        return 'Permission denied.'

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with open('user_data.json', 'r') as f:
            user_data = json.load(f)
        if username in user_data and user_data[username]['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = user_data[username].get('is_admin', False)  # 从user_data.json中读取用户是否为管理员信息
            return redirect(url_for('file_reader'))
        else:
            return 'Invalid username/password'
    return render_template('login.html')


# 验证用户身份
def authenticate_user(username, password):
    with open(USER_DATA_FILE, 'r') as f:
        user_data = json.load(f)
    if username in user_data:
        return user_data[username]['password'] == password
    return False

# 文件管理器路由
@app.route('/file_reader', methods=['GET', 'POST'])
def file_reader():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        file_path = request.form['file_path']

        # 检查目录路径是否合法
        if file_path != '/' and (not all(char.isalnum() or char in ['/', '_', '-', '.'] for char in file_path) or '..' in file_path):
            abort(400, 'Invalid directory path')

        # 检查目录路径是否包含 'flag'
        if 'flag' in file_path:
            abort(400, 'Nah, flag not allowed')

        # 检查用户是否有权限访问特定文件或目录
        if not check_permissions(file_path, session['username']):
            abort(403, 'You are not authorized to read this file')

        file_content = read_file(file_path, session['username'])

        # 检查文件内容是否为空，如果为空则文件不存在
        if not file_content:
            abort(404, 'File not found')

        return render_template('file_reader.html', file_content=file_content)

    return render_template('file_reader.html', file_content=None)

# 退出登录路由
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# 获取权限页面路由
@app.route('/get_user_permissions', methods=['GET', 'POST'])
def get_user_permissions():
    if request.method == 'GET':
        # 渲染模板并传递用户列表
        with open('user_data.json', 'r') as f:
            user_data = json.load(f)
        users = list(user_data.keys())
        return render_template('get_user_permissions.html', users=users)

    elif request.method == 'POST':
        # 获取POST请求中选择的用户
        selected_user = request.form['user']

        # 从 JSON 文件中读取用户信息
        with open('user_data.json', 'r') as f:
            user_data = json.load(f)

        # 获取特定用户的权限配置
        permissions = user_data.get(selected_user, {}).get('permissions', {})

        return jsonify(permissions)

# 更新权限页面路由
@app.route('/update_permissions', methods=['GET', 'POST'])
def update_permissions():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if not session.get('is_admin'):
        abort(403, 'User not allowed')

    # 从 JSON 文件中读取用户信息
    with open('user_data.json', 'r') as f:
        user_data = json.load(f)

    if request.method == 'GET':
        # 如果用户不是管理员，只允许修改自己的权限
        if not session.get('is_admin'):
            users = [session['username']]
        else:
            users = [user for user, data in user_data.items()]
            # 提取所有非管理员用户的用户名
            # users = [user for user, data in user_data.items() if not data['is_admin']]
        return render_template('update_permissions.html', users=users)

    elif request.method == 'POST':
        # 获取表单数据
        user = request.form['user']
        path = request.form['path']
        access = request.form['access']

        # 检查新添加的目录路径是否只包含 '/'、'_'、'-'数字和字母，且以'/'结尾
        if path != '/' and not (path.endswith('/') and all(char.isalnum() or char in ['/', '_', '-'] for char in path[:-1])):
            abort(400, 'Invalid directory path')

        # 检查新添加的目录路径是否包含 'flag'
        if 'flag' in path:
            abort(400, 'Nah, flag not allowed')

        # 如果用户不是管理员，只允许修改自己的权限
        if not session.get('is_admin') and user != session['username']:
            abort(403, "You are not authorized to modify other users' permissions")

        # 检查添加的目录是否与已存在的目录相同
        if path in user_data[user]['permissions']:
            abort(400, "Directory already exists")

        # 更新用户权限
        user_data[user]['permissions'][path] = access
        with open('user_data.json', 'w') as f:
            json.dump(user_data, f, indent=4)

        return redirect('/update_permissions')

# 文件上传路由
@app.route('/file_uploader', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            abort(400, 'No file part')

        file = request.files['file']

        if file.filename == '':
            abort(400, 'No selected file')

        if not all(char.isalnum() or char in ['.', '_', '-'] for char in file.filename):
            abort(400, 'Invalid filename')

        # 检查目录下是否已经存在同名文件
        target_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(target_path):
            abort(400, "File already existed")

        if file:
            file.save(target_path)
            return 'File uploaded successfully'

    # 如果是 GET 请求，则返回文件上传页面
    return render_template('file_uploader.html')


# 根路径重定向至登录页面
@app.route('/')
def index():
    return redirect(url_for('login'))

def check_permissions(file_path, username):
    # 检查用户是否有权限访问特定文件或目录

    # 从 JSON 文件中读取用户信息
    with open('user_data.json', 'r') as f:
        user_data = json.load(f)

    # 获取用户的权限配置
    user_permissions = user_data.get(username, {}).get('permissions', {})

    # 检查文件路径是否与用户权限配置中的某个路径匹配
    for permission_path in user_permissions.keys():
        if file_path.startswith(permission_path):
            return True

    return False

@app.route('/error')
def error():
    with open('/flag', 'r') as flag:
        flag = flag.read()
    assert flag == "dutctf{Fak3_fl@g_2333}"
    return render_template('error.html')

if __name__ == '__main__':
    # 初始化用户数据文件
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'w') as f:
            json.dump({}, f)
    app.run(host='0.0.0.0', port='5000', debug=True)
