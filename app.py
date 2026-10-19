from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import bcrypt
import datetime
from functools import wraps
from markupsafe import escape

app = Flask(__name__)
# 配置 SQLite 数据库 (自动在当前目录生成 app.db)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'your-super-secret-key' # JWT 签名密钥
db = SQLAlchemy(app)

# --- 数据库模型定义 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# --- 初始化数据库并创建一个测试用户 ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        hashed_pw = bcrypt.hashpw("123456".encode('utf-8'), bcrypt.gensalt())
        admin_user = User(username="admin", password_hash=hashed_pw.decode('utf-8'))
        db.session.add(admin_user)
        db.session.commit()

# --- 安全中间件：JWT 验证装饰器 ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # 从请求头 Authorization: Bearer <token> 中获取
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # 验证 Token 的签名和有效期
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# --- 接口 1: 登录 (POST /auth/login) ---
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Could not verify'}), 400

    # 安全防注入：使用 ORM 查询，底层是参数化查询
    user = User.query.filter_by(username=data['username']).first()

    # 使用 bcrypt 验证密码
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash.encode('utf-8')):
        # 生成 JWT，有效期 1 小时
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials'}), 401

# --- 接口 2: 获取受保护数据 (GET /api/data) ---
@app.route('/api/data', methods=['GET'])
@token_required # 挂载验证中间件
def get_data(current_user):
    # 安全防 XSS：即使用户名包含 <script>，Flask 返回 JSON 时默认安全。
    # 如果用到了 HTML 渲染，必须使用 escape() 转义。
    safe_username = escape(current_user.username)
    
    # 模拟返回数据
    return jsonify({
        "message": f"Hello {safe_username}, this is protected data!",
        "data": [
            {"id": 1, "title": "Secure Post 1"},
            {"id": 2, "title": "Secure Post 2"}
        ]
    })

# --- 接口 3: 自己设计的接口 (POST /api/register) ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing data'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400

    # 安全防注入：ORM 插入
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    new_user = User(username=data['username'], password_hash=hashed_pw.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True, port=5000)