"""
EN启动 - 卡密系统后端服务器
依赖: pip install flask cryptography
启动: python server.py
"""
import os
import sqlite3
import hashlib
import secrets
import json
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Render/gunicorn: init on import
init_keys()
init_db()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'enen_cards.db')
KEY_DIR = os.path.join(BASE_DIR, 'keys')

# ============ RSA密钥管理 ============

def init_keys():
    """初始化RSA密钥对，如果不存在则生成"""
    os.makedirs(KEY_DIR, exist_ok=True)
    private_path = os.path.join(KEY_DIR, 'private_key.pem')
    public_path = os.path.join(KEY_DIR, 'public_key.pem')

    if not os.path.exists(private_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # 保存私钥
        with open(private_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 保存公钥
        with open(public_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[*] RSA密钥对已生成")

    return private_path, public_path


def load_private_key():
    private_path = os.path.join(KEY_DIR, 'private_key.pem')
    with open(private_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key():
    public_path = os.path.join(KEY_DIR, 'public_key.pem')
    with open(public_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def get_public_key_base64():
    """获取公钥的base64格式（供客户端使用）"""
    public_path = os.path.join(KEY_DIR, 'public_key.pem')
    with open(public_path, 'rb') as f:
        content = f.read()
    import base64
    # 去掉PEM头尾，只保留base64内容
    lines = content.decode().strip().split('\n')
    b64 = ''.join(line for line in lines if not line.startswith('-----'))
    return b64

# ============ 数据库 ============

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_key TEXT UNIQUE NOT NULL,
            card_hash TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'unused',
            device_fingerprint TEXT,
            device_info TEXT,
            activated_at TIMESTAMP,
            expires_days INTEGER NOT NULL,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            banned INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS so_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            md5sum TEXT NOT NULL,
            description TEXT,
            force_update INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS card_versions (
            card_key TEXT NOT NULL,
            version TEXT NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (card_key)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_tokens (
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS kami_pool (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_key TEXT UNIQUE NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS linyu_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel INTEGER NOT NULL,
            version TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            md5sum TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS card_sessions (
            card_key TEXT NOT NULL,
            device_fingerprint TEXT NOT NULL,
            last_heartbeat TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (card_key, device_fingerprint)
        )
    ''')
    conn.commit()
    conn.close()


# Session timeout: no heartbeat within this period = offline, others can grab
SESSION_TIMEOUT_SECONDS = 60


def update_heartbeat(conn, card_key, device_fp):
    conn.execute('''
        INSERT INTO card_sessions (card_key, device_fingerprint, last_heartbeat)
        VALUES (?, ?, ?)
        ON CONFLICT(card_key, device_fingerprint)
        DO UPDATE SET last_heartbeat = excluded.last_heartbeat
    ''', (card_key, device_fp, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()


def check_device_online(conn, card_key, current_device_fp):
    threshold = (datetime.now() - timedelta(seconds=SESSION_TIMEOUT_SECONDS)).strftime('%Y-%m-%d %H:%M:%S')
    row = conn.execute('''
        SELECT device_fingerprint FROM card_sessions
        WHERE card_key = ? AND device_fingerprint != ? AND last_heartbeat > ?
        ORDER BY last_heartbeat DESC LIMIT 1
    ''', (card_key, current_device_fp, threshold)).fetchone()
    if row:
        return True, row['device_fingerprint'] if hasattr(row, 'keys') else row[0]
    return False, None


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============ 卡密池迁移辅助函数 ============

def migrate_kami_to_cards(conn, card_key):
    """
    如果卡密只在 kami_pool 中存在，自动迁移到 cards 表（未激活状态）。
    迁移后返回该卡密记录，否则返回 None。
    解决"卡密池上传后无法激活"的问题。
    """
    row = conn.execute('SELECT card_key FROM kami_pool WHERE card_key = ?', (card_key,)).fetchone()
    if not row:
        return None
    existing = conn.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,)).fetchone()
    if existing:
        return existing
    expires_days = 30
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    card_hash = hash_card_key(card_key)
    conn.execute(
        "INSERT INTO cards (card_key, card_hash, status, banned, expires_days, created_at) VALUES (?, ?, 'unused', 0, ?, ?)",
        (card_key, card_hash, expires_days, created_at)
    )
    conn.commit()
    migrated = conn.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,)).fetchone()
    print(f"[迁移] 卡密 {card_key} 从 kami_pool 迁移到 cards 表")
    return migrated


# ============ 工具函数 ============

def generate_card_key():
    """生成卡密: EN-XXXX-XXXX-XXXX-XXXX"""
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    parts = []
    for _ in range(4):
        parts.append(''.join(secrets.choice(chars) for _ in range(4)))
    return 'EN-' + '-'.join(parts)


def hash_card_key(card_key):
    """SHA256哈希卡密"""
    return hashlib.sha256(card_key.encode()).hexdigest()


def sign_data(data: str) -> str:
    """用RSA私钥签名数据"""
    private_key = load_private_key()
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    import base64
    return base64.b64encode(signature).decode()


def verify_signature(data: str, signature_b64: str) -> bool:
    """用RSA公钥验证签名"""
    try:
        import base64
        public_key = load_public_key()
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def make_activation_token(card_key: str, device_fp: str, expires_at: str) -> str:
    """生成激活凭证（RSA签名）"""
    payload = f"{card_key}|{device_fp}|{expires_at}"
    signature = sign_data(payload)
    import base64
    token = base64.b64encode(f"{payload}||{signature}".encode()).decode()
    return token

# ============ API接口 ============

@app.route('/api/activate', methods=['POST'])
def activate_card():
    """
    激活卡密（绑定设备）
    请求: { card_key, device_fingerprint, device_info }
    响应: { success, message, activation_token, expires_at } 或 { success: false, message }
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "无效请求"}), 400

    card_key = data.get('card_key', '').strip()
    device_fp = data.get('device_fingerprint', '').strip()
    device_info = data.get('device_info', '').strip()

    print(f"[ACTIVATE] 收到激活请求: card_key={card_key}, device_fp={device_fp[:20]}..., device_info={device_info[:30]}")

    if not card_key or not device_fp:
        return jsonify({"success": False, "message": "参数缺失"}), 400

    conn = get_db()
    c = conn.cursor()

    # 查找卡密（先查 cards 表，没有则从 kami_pool 迁移）
    card = c.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,)).fetchone()
    if not card:
        print(f"[ACTIVATE] cards 表未找到 {card_key}，尝试从 kami_pool 迁移")
        card = migrate_kami_to_cards(conn, card_key)

    if not card:
        conn.close()
        print(f"[ACTIVATE] 卡密 {card_key} 不存在")
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    print(f"[ACTIVATE] 找到卡密 {card_key}, 当前状态: status={card['status']}, device_fp={card['device_fingerprint']}")

    if card['banned']:
        conn.close()
        return jsonify({"success": False, "message": "卡密已被封禁"}), 403

    # Check if another device is currently using this card (online exclusive)
    other_online, other_fp = check_device_online(conn, card_key, device_fp)
    if other_online:
        conn.close()
        print(f"[ACTIVATE] Denied: card {card_key} in use by {other_fp[:20]}...")
        return jsonify({"success": False, "message": "卡密正在其他设备使用中，请稍后再试"}), 403

    if card['status'] == 'activated':
        # Same device or no other online -> allow (re)activate, update binding
        expires_days = card['expires_days']
        activated_at = datetime.now()
        expires_at = (activated_at + timedelta(days=expires_days)).strftime('%Y-%m-%d %H:%M:%S')

        c.execute('''
            UPDATE cards SET status = 'activated', device_fingerprint = ?, device_info = ?,
                             activated_at = ?, expires_at = ?
            WHERE card_key = ?
        ''', (device_fp, device_info, activated_at.strftime('%Y-%m-%d %H:%M:%S'),
              expires_at, card_key))
        conn.commit()
        update_heartbeat(conn, card_key, device_fp)
        token = make_activation_token(card_key, device_fp, expires_at)
        conn.close()
        return jsonify({
            "success": True,
            "message": "激活成功" if card['device_fingerprint'] != device_fp else "已激活（同一设备）",
            "activation_token": token,
            "expires_at": expires_at
        })

    # New activation
    expires_days = card['expires_days']
    activated_at = datetime.now()
    expires_at = (activated_at + timedelta(days=expires_days)).strftime('%Y-%m-%d %H:%M:%S')

    c.execute('''
        UPDATE cards SET status = 'activated', device_fingerprint = ?, device_info = ?,
                         activated_at = ?, expires_at = ?
        WHERE card_key = ?
    ''', (device_fp, device_info, activated_at.strftime('%Y-%m-%d %H:%M:%S'),
          expires_at, card_key))
    conn.commit()
    update_heartbeat(conn, card_key, device_fp)

    token = make_activation_token(card_key, device_fp, expires_at)
    conn.close()

    return jsonify({
        "success": True,
        "message": "激活成功",
        "activation_token": token,
        "expires_at": expires_at
    })


@app.route('/api/verify', methods=['POST'])
def verify_card():
    """
    在线验证卡密状态（用于封禁失效检查）
    请求: { card_key, device_fingerprint }
    响应: { valid, expires_at }
    """
    data = request.get_json()
    if not data:
        return jsonify({"valid": False, "message": "无效请求"}), 400

    card_key = data.get('card_key', '').strip()
    device_fp = data.get('device_fingerprint', '').strip()

    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,)).fetchone()
    if not card:
        card = migrate_kami_to_cards(conn, card_key)

    if not card:
        conn.close()
        print(f"[VERIFY] 卡密不存在: {card_key}")
        return jsonify({"valid": False, "message": "卡密不存在"})

    print(f"[VERIFY] card_key={card_key}, status={card['status']}, device_fp_in_db={card['device_fingerprint']}, device_fp_req={device_fp}")

    if card['banned']:
        conn.close()
        return jsonify({"valid": False, "message": "卡密已封禁"})

    if card['status'] != 'activated':
        conn.close()
        return jsonify({"valid": False, "message": "卡密未激活"})

    # Unlimited bind mode: no longer require device_fingerprint match
    # But check online exclusive: is another device using this card?
    other_online, other_fp = check_device_online(conn, card_key, device_fp)
    if other_online:
        conn.close()
        print(f"[VERIFY] Denied: card {card_key} in use by {other_fp[:20]}...")
        return jsonify({"valid": False, "message": "卡密正在其他设备使用中"})

    # Update heartbeat for current device
    update_heartbeat(conn, card_key, device_fp)
    conn.close()

    # Check expiry
    expires_at = card['expires_at']
    if datetime.now() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S'):
        return jsonify({"valid": False, "message": "卡密已过期"})

    return jsonify({"valid": True, "expires_at": expires_at})


@app.route('/api/public_key', methods=['GET'])
def get_public_key():
    """获取服务器RSA公钥（供客户端Native层验签）"""
    return jsonify({"public_key": get_public_key_base64()})


# ============ 云更新接口 ============

SO_UPLOAD_DIR = os.path.join(BASE_DIR, 'so_uploads')


# ============ 卡密池接口（后台上传 txt，APP 端下拉拉取） ============

@app.route('/api/kami/list', methods=['GET'])
def kami_list():
    """APP端获取卡密池列表（用于下拉填充，无需鉴权）"""
    conn = get_db()
    rows = conn.execute('SELECT card_key FROM kami_pool ORDER BY id ASC').fetchall()
    conn.close()
    return jsonify({"success": True, "kamis": [r['card_key'] for r in rows]})


@app.route('/api/admin/kami/upload', methods=['POST'])
def admin_upload_kami():
    """管理后台上传卡密.txt文件，自动识别并入库"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    if 'file' not in request.files:
        # 也支持直接提交文本
        text = request.form.get('text', '')
        if not text:
            return jsonify({"success": False, "message": "请选择文件或粘贴卡密文本"}), 400
    else:
        file = request.files['file']
        try:
            raw = file.read()
            # 兼容 UTF-8 BOM、UTF-16、GBK 等常见编码
            if raw.startswith(b'\xef\xbb\xbf'):
                text = raw[3:].decode('utf-8', errors='ignore')
            elif raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
                text = raw.decode('utf-16', errors='ignore')
            else:
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    text = raw.decode('gbk', errors='ignore')
        except Exception as e:
            return jsonify({"success": False, "message": f"文件读取失败: {e}"}), 400

    # 解析卡密：每行一个，去空行、去注释、去空白字符、去重
    lines = [ln.strip().replace('\u200b', '').replace('\ufeff', '') for ln in text.splitlines()]
    kamis = [ln for ln in lines if ln and not ln.startswith('#')]
    kamis = list(dict.fromkeys(kamis))  # 去重保序

    if not kamis:
        return jsonify({"success": False, "message": "未识别到有效卡密"}), 400

    conn = get_db()
    c = conn.cursor()
    inserted = 0
    for k in kamis:
        # 仅写入卡密池（用于APP端下拉显示），与 cards 激活验证表无关
        try:
            c.execute('INSERT INTO kami_pool (card_key) VALUES (?)', (k,))
            inserted += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"导入完成：共 {len(kamis)} 个，新增 {inserted} 个",
        "count": len(kamis),
        "inserted": inserted
    })


@app.route('/api/admin/kami/pool/list', methods=['GET'])
def admin_kami_pool_list():
    """管理后台查看卡密池（仅返回数量，不列出卡密详情）"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM kami_pool').fetchone()[0]
    conn.close()
    return jsonify({"success": True, "count": count})


@app.route('/api/admin/kami/pool/clear', methods=['POST'])
def admin_kami_pool_clear():
    """清空卡密池"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401
    conn = get_db()
    conn.execute('DELETE FROM kami_pool')
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "卡密池已清空"})


@app.route('/api/update/check', methods=['GET'])
def check_so_update():
    """检查.so文件更新
    请求参数: ?current_version=xxx&card_key=xxx
    如果card_key有指定版本，优先返回该版本；否则返回最新版本
    响应: { has_update, version, filename, file_size, md5sum, description, force_update, download_url }
    """
    current_version = request.args.get('current_version', '')
    card_key = request.args.get('card_key', '').strip()

    conn = get_db()

    # 优先检查卡密是否有指定版本
    assigned_version = None
    if card_key:
        row = conn.execute(
            'SELECT version FROM card_versions WHERE card_key = ?', (card_key,)
        ).fetchone()
        if row:
            assigned_version = row['version']

    if assigned_version:
        # 返回卡密指定版本
        target = conn.execute(
            'SELECT * FROM so_updates WHERE version = ? ORDER BY id DESC LIMIT 1',
            (assigned_version,)
        ).fetchone()
    else:
        # 返回最新版本
        target = conn.execute(
            'SELECT * FROM so_updates ORDER BY id DESC LIMIT 1'
        ).fetchone()

    conn.close()

    if not target:
        return jsonify({"has_update": False, "message": "暂无可用更新"})

    if target['version'] == current_version:
        return jsonify({"has_update": False, "message": "已是最新版本"})

    return jsonify({
        "has_update": True,
        "version": target['version'],
        "filename": target['filename'],
        "file_size": target['file_size'],
        "md5sum": target['md5sum'],
        "description": target['description'] or '',
        "force_update": True,  # 统一强制更新
        "download_url": f"/api/update/download/{target['id']}"
    })


@app.route('/api/update/download/<int:update_id>', methods=['GET'])
def download_so_update(update_id):
    """下载.so文件"""
    conn = get_db()
    row = conn.execute('SELECT * FROM so_updates WHERE id = ?', (update_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "文件不存在"}), 404

    file_path = row['file_path']
    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "文件已丢失"}), 404

    from flask import send_file
    return send_file(file_path, as_attachment=True, download_name=row['filename'])


@app.route('/api/admin/so/upload', methods=['POST'])
def admin_upload_so():
    """上传.so文件更新"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    os.makedirs(SO_UPLOAD_DIR, exist_ok=True)

    if 'file' not in request.files:
        return jsonify({"success": False, "message": "请选择文件"}), 400

    file = request.files['file']
    if not file.filename or not file.filename.endswith('.so'):
        return jsonify({"success": False, "message": "请上传.so文件"}), 400

    version = request.form.get('version', '').strip()
    if not version:
        return jsonify({"success": False, "message": "请填写版本号"}), 400

    description = request.form.get('description', '').strip()
    force_update = int(request.form.get('force_update', 0))

    # 保存文件
    filename = file.filename
    save_path = os.path.join(SO_UPLOAD_DIR, f"v{version}_{filename}")
    file.save(save_path)

    # 计算文件大小和MD5
    file_size = os.path.getsize(save_path)
    import hashlib as hl
    md5sum = hl.md5()
    with open(save_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5sum.update(chunk)
    md5sum = md5sum.hexdigest()

    # 写入数据库
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT INTO so_updates (version, filename, file_path, file_size, md5sum, description, force_update)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (version, filename, save_path, file_size, md5sum, description, force_update))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"上传成功: v{version}",
        "version": version,
        "file_size": file_size,
        "md5sum": md5sum
    })


@app.route('/api/admin/so/list', methods=['GET'])
def admin_so_list():
    """列出所有.so更新版本"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    conn = get_db()
    rows = conn.execute('SELECT * FROM so_updates ORDER BY id DESC').fetchall()
    conn.close()

    return jsonify({"success": True, "updates": [dict(r) for r in rows]})


@app.route('/api/admin/so/delete', methods=['POST'])
def admin_so_delete():
    """删除.so更新版本"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    update_id = data.get('id')

    conn = get_db()
    row = conn.execute('SELECT * FROM so_updates WHERE id = ?', (update_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "版本不存在"}), 404

    # 删除文件
    try:
        if os.path.exists(row['file_path']):
            os.remove(row['file_path'])
    except Exception:
        pass

    conn.execute('DELETE FROM so_updates WHERE id = ?', (update_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"已删除 v{row['version']}"})


@app.route('/api/admin/so/assign', methods=['POST'])
def admin_assign_version():
    """为卡密指定.so版本"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()
    version = data.get('version', '').strip()

    if not card_key or not version:
        return jsonify({"success": False, "message": "卡密和版本号不能为空"}), 400

    conn = get_db()
    c = conn.cursor()

    # 验证卡密存在
    card = c.execute('SELECT id FROM cards WHERE card_key = ?', (card_key,)).fetchone()
    if not card:
        conn.close()
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    # 验证版本存在
    so = c.execute('SELECT id FROM so_updates WHERE version = ? ORDER BY id DESC LIMIT 1', (version,)).fetchone()
    if not so:
        conn.close()
        return jsonify({"success": False, "message": f"版本 v{version} 不存在"}), 404

    # 写入绑定（REPLACE覆盖旧值）
    c.execute('REPLACE INTO card_versions (card_key, version) VALUES (?, ?)', (card_key, version))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"已将 {card_key} 指定到 v{version}"})


@app.route('/api/admin/so/assign/list', methods=['GET'])
def admin_assign_list():
    """查询所有卡密版本分配"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    conn = get_db()
    rows = conn.execute('SELECT * FROM card_versions ORDER BY assigned_at DESC').fetchall()
    conn.close()

    return jsonify({"success": True, "assigns": [dict(r) for r in rows]})


@app.route('/api/admin/so/assign/delete', methods=['POST'])
def admin_assign_delete():
    """删除卡密版本分配"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()

    conn = get_db()
    result = conn.execute('DELETE FROM card_versions WHERE card_key = ?', (card_key,))
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({"success": False, "message": "分配不存在"}), 404

    return jsonify({"success": True, "message": f"已取消 {card_key} 的版本指定"})


@app.route('/api/admin/so/versions', methods=['GET'])
def admin_so_versions():
    """获取所有可用版本号列表（供分配下拉选择）"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    conn = get_db()
    rows = conn.execute('SELECT DISTINCT version FROM so_updates ORDER BY id DESC').fetchall()
    conn.close()

    return jsonify({"success": True, "versions": [r['version'] for r in rows]})


# ============ 林宇模块接口 ============

LINYU_UPLOAD_DIR = os.path.join(BASE_DIR, 'linyu_uploads')
LINYU_CHANNELS = {1: "过验证", 2: "驱动", 3: "内核"}


@app.route('/api/linyu/check', methods=['GET'])
def linyu_check():
    conn = get_db()
    result = {}
    for ch in [1, 2, 3]:
        row = conn.execute(
            'SELECT * FROM linyu_files WHERE channel = ? ORDER BY id DESC LIMIT 1', (ch,)
        ).fetchone()
        if row:
            result[str(ch)] = {
                "version": row['version'],
                "filename": row['filename'],
                "file_size": row['file_size'],
                "md5sum": row['md5sum'],
                "download_url": f"/api/linyu/download/{ch}",
                "channel_name": LINYU_CHANNELS.get(ch, str(ch)),
            }
    conn.close()
    return jsonify({"success": True, "channels": result})


@app.route('/api/linyu/download/<int:channel>', methods=['GET'])
def linyu_download(channel):
    conn = get_db()
    row = conn.execute(
        'SELECT * FROM linyu_files WHERE channel = ? ORDER BY id DESC LIMIT 1', (channel,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "文件不存在"}), 404

    file_path = row['file_path']
    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "文件已丢失"}), 404

    from flask import send_file
    return send_file(file_path, as_attachment=True, download_name=row['filename'])

@app.route('/api/admin/linyu/upload', methods=['POST'])
def admin_upload_linyu():
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    os.makedirs(LINYU_UPLOAD_DIR, exist_ok=True)

    if 'file' not in request.files:
        return jsonify({"success": False, "message": "请选择文件"}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"success": False, "message": "请选择文件"}), 400

    channel = int(request.form.get('channel', 0))
    if channel not in [1, 2, 3]:
        return jsonify({"success": False, "message": "通道必须是1、2或3"}), 400

    version = request.form.get('version', '').strip()
    if not version:
        return jsonify({"success": False, "message": "请填写版本号"}), 400

    filename = file.filename
    save_path = os.path.join(LINYU_UPLOAD_DIR, f"ch{channel}_v{version}_{filename}")
    file.save(save_path)

    file_size = os.path.getsize(save_path)
    import hashlib as hl
    md5sum = hl.md5()
    with open(save_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5sum.update(chunk)
    md5sum = md5sum.hexdigest()

    conn = get_db()
    conn.execute(
        'INSERT INTO linyu_files (channel, version, filename, file_path, file_size, md5sum) VALUES (?, ?, ?, ?, ?, ?)',
        (channel, version, filename, save_path, file_size, md5sum)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"上传成功: {LINYU_CHANNELS[channel]} v{version}",
        "version": version,
        "file_size": file_size,
        "md5sum": md5sum
    })


@app.route('/api/admin/linyu/list', methods=['GET'])
def admin_linyu_list():
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    conn = get_db()
    rows = conn.execute('SELECT * FROM linyu_files ORDER BY id DESC').fetchall()
    conn.close()

    return jsonify({"success": True, "files": [dict(r) for r in rows]})


@app.route('/api/admin/linyu/delete', methods=['POST'])
def admin_linyu_delete():
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    file_id = data.get('id')

    conn = get_db()
    row = conn.execute('SELECT * FROM linyu_files WHERE id = ?', (file_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "文件不存在"}), 404

    try:
        if os.path.exists(row['file_path']):
            os.remove(row['file_path'])
    except Exception:
        pass

    conn.execute('DELETE FROM linyu_files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "已删除"})


# ============ 管理接口 ============

ADMIN_TOKEN = os.environ.get('ENEN_ADMIN_TOKEN', 'enen_admin_2024_secret')

def check_admin_auth():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        token = request.args.get('t', '')
    return token == ADMIN_TOKEN


@app.route('/api/admin/generate', methods=['POST'])
def admin_generate_cards():
    """批量生成卡密"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    count = data.get('count', 1)
    expires_days = data.get('expires_days', 30)

    if count > 1000:
        return jsonify({"success": False, "message": "单次最多生成1000个"}), 400

    conn = get_db()
    c = conn.cursor()
    cards = []
    for _ in range(count):
        while True:
            card_key = generate_card_key()
            card_hash = hash_card_key(card_key)
            try:
                c.execute('''
                    INSERT INTO cards (card_key, card_hash, expires_days, status)
                    VALUES (?, ?, ?, 'unused')
                ''', (card_key, card_hash, expires_days))
                cards.append(card_key)
                break
            except sqlite3.IntegrityError:
                continue
    conn.commit()
    conn.close()

    return jsonify({"success": True, "count": len(cards), "cards": cards})


@app.route('/api/admin/list', methods=['GET'])
def admin_list_cards():
    """查询卡密列表"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    status = request.args.get('status', '')  # unused/activated/banned
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))

    conn = get_db()
    c = conn.cursor()

    if status == 'banned':
        c.execute('SELECT * FROM cards WHERE banned = 1 ORDER BY id DESC LIMIT ? OFFSET ?',
                  (per_page, (page - 1) * per_page))
        cards = [dict(row) for row in c.fetchall()]
        total = c.execute('SELECT COUNT(*) as cnt FROM cards WHERE banned = 1').fetchone()['cnt']
    elif status:
        c.execute('SELECT * FROM cards WHERE status = ? ORDER BY id DESC LIMIT ? OFFSET ?',
                  (status, per_page, (page - 1) * per_page))
        cards = [dict(row) for row in c.fetchall()]
        total = c.execute('SELECT COUNT(*) as cnt FROM cards WHERE status = ?', (status,)).fetchone()['cnt']
    else:
        c.execute('SELECT * FROM cards ORDER BY id DESC LIMIT ? OFFSET ?', (per_page, (page - 1) * per_page))
        cards = [dict(row) for row in c.fetchall()]
        total = c.execute('SELECT COUNT(*) as cnt FROM cards').fetchone()['cnt']

    conn.close()

    # 脱敏：不返回card_hash
    for card in cards:
        card.pop('card_hash', None)

    return jsonify({"success": True, "total": total, "page": page, "cards": cards})


@app.route('/api/admin/ban', methods=['POST'])
def admin_ban_card():
    """封禁卡密（同时解绑设备）"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()

    conn = get_db()
    c = conn.cursor()
    result = c.execute('''
        UPDATE cards 
        SET banned = 1, status = 'unused', device_fingerprint = NULL, activated_at = NULL, expires_at = NULL
        WHERE card_key = ?
    ''', (card_key,))
    c.execute('DELETE FROM card_sessions WHERE card_key = ?', (card_key,))
    conn.commit()
    affected = result.rowcount
    conn.close()

    if affected == 0:
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    return jsonify({"success": True, "message": f"已封禁并解绑: {card_key}"})


@app.route('/api/admin/unban', methods=['POST'])
def admin_unban_card():
    """解封卡密"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()

    conn = get_db()
    c = conn.cursor()
    result = c.execute('UPDATE cards SET banned = 0 WHERE card_key = ?', (card_key,))
    conn.commit()
    affected = result.rowcount
    conn.close()

    if affected == 0:
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    return jsonify({"success": True, "message": f"已解封: {card_key}"})


@app.route('/api/admin/delete', methods=['POST'])
def admin_delete_card():
    """删除卡密"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()

    conn = get_db()
    c = conn.cursor()
    result = c.execute('DELETE FROM cards WHERE card_key = ?', (card_key,))
    conn.commit()
    affected = result.rowcount
    conn.close()

    if affected == 0:
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    return jsonify({"success": True, "message": f"已删除: {card_key}"})


@app.route('/api/admin/unbind', methods=['POST'])
def admin_unbind_card():
    """解绑设备（重置为未激活）"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()

    conn = get_db()
    c = conn.cursor()
    result = c.execute('''
        UPDATE cards SET status = 'unused', device_fingerprint = NULL, device_info = NULL,
                         activated_at = NULL, expires_at = NULL
        WHERE card_key = ?
    ''', (card_key,))
    c.execute('DELETE FROM card_sessions WHERE card_key = ?', (card_key,))
    conn.commit()
    affected = result.rowcount
    conn.close()

    if affected == 0:
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    return jsonify({"success": True, "message": f"已解绑: {card_key}"})


@app.route('/api/admin/extend', methods=['POST'])
def admin_extend_card():
    """延期卡密"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    data = request.get_json() or {}
    card_key = data.get('card_key', '').strip()
    add_days = data.get('add_days', 30)

    conn = get_db()
    c = conn.cursor()
    card = c.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,)).fetchone()

    if not card:
        conn.close()
        return jsonify({"success": False, "message": "卡密不存在"}), 404

    if card['status'] != 'activated' or not card['expires_at']:
        # 未激活的卡密，直接增加有效期天数
        c.execute('UPDATE cards SET expires_days = expires_days + ? WHERE card_key = ?', (add_days, card_key))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"已增加{add_days}天有效期（未激活卡密）"})

    # 已激活的卡密，延长到期时间
    current_expires = datetime.strptime(card['expires_at'], '%Y-%m-%d %H:%M:%S')
    new_expires = current_expires + timedelta(days=add_days)
    new_expires_str = new_expires.strftime('%Y-%m-%d %H:%M:%S')
    c.execute('UPDATE cards SET expires_at = ?, expires_days = expires_days + ? WHERE card_key = ?',
              (new_expires_str, add_days, card_key))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"已延期{add_days}天，新到期: {new_expires_str}"})


@app.route('/api/admin/export', methods=['GET'])
def admin_export_cards():
    """导出卡密"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    status = request.args.get('status', '')
    fmt = request.args.get('format', 'txt')

    conn = get_db()
    c = conn.cursor()
    if status:
        cards = c.execute('SELECT card_key, status, expires_days, expires_at FROM cards WHERE status = ? ORDER BY id', (status,)).fetchall()
    else:
        cards = c.execute('SELECT card_key, status, expires_days, expires_at FROM cards ORDER BY id').fetchall()
    conn.close()

    if fmt == 'csv':
        import io
        output = io.StringIO()
        output.write('卡密,状态,有效天数,到期时间\n')
        for card in cards:
            output.write(f"{card['card_key']},{card['status']},{card['expires_days']},{card['expires_at'] or ''}\n")
        from flask import Response
        return Response(output.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition': 'attachment; filename=cards.csv'})

    # 默认返回JSON
    return jsonify({"success": True, "cards": [dict(c) for c in cards]})


@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    """统计信息"""
    if not check_admin_auth():
        return jsonify({"success": False, "message": "未授权"}), 401

    conn = get_db()
    c = conn.cursor()
    total = c.execute('SELECT COUNT(*) as cnt FROM cards').fetchone()['cnt']
    unused = c.execute("SELECT COUNT(*) as cnt FROM cards WHERE status = 'unused'").fetchone()['cnt']
    activated = c.execute("SELECT COUNT(*) as cnt FROM cards WHERE status = 'activated'").fetchone()['cnt']
    banned = c.execute('SELECT COUNT(*) as cnt FROM cards WHERE banned = 1').fetchone()['cnt']
    conn.close()

    return jsonify({
        "success": True,
        "stats": {
            "total": total,
            "unused": unused,
            "activated": activated,
            "banned": banned
        }
    })


# ============ Web管理后台 ============

ADMIN_PAGE_HTML = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EN启动 - 卡密管理后台</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',system-ui,sans-serif; background:#f0f2f5; color:#333; }
.header { background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; padding:20px 30px; display:flex; justify-content:space-between; align-items:center; }
.header h1 { font-size:22px; }
.header .user { font-size:14px; opacity:0.9; }
.container { max-width:1200px; margin:20px auto; padding:0 15px; }
.stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:15px; margin-bottom:20px; }
.stat-card { background:#fff; border-radius:12px; padding:20px; text-align:center; box-shadow:0 2px 8px rgba(0,0,0,0.08); transition:transform 0.2s; }
.stat-card:hover { transform:translateY(-3px); }
.stat-card .num { font-size:32px; font-weight:700; }
.stat-card .label { font-size:13px; color:#888; margin-top:5px; }
.stat-card.blue .num { color:#4f8cff; }
.stat-card.green .num { color:#52c41a; }
.stat-card.orange .num { color:#fa8c16; }
.stat-card.red .num { color:#f5222d; }
.panel { background:#fff; border-radius:12px; padding:20px; margin-bottom:20px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.panel-title { font-size:16px; font-weight:600; margin-bottom:15px; display:flex; align-items:center; gap:8px; }
.panel-title::before { content:''; width:4px; height:16px; background:#667eea; border-radius:2px; }
.gen-form { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; }
.gen-form .field { display:flex; flex-direction:column; gap:4px; }
.gen-form label { font-size:12px; color:#888; }
.gen-form input { border:1px solid #ddd; border-radius:8px; padding:8px 12px; font-size:14px; width:120px; }
.btn { border:none; border-radius:8px; padding:9px 18px; font-size:14px; cursor:pointer; transition:all 0.2s; }
.btn-primary { background:#667eea; color:#fff; }
.btn-primary:hover { background:#5568d3; }
.btn-danger { background:#f5222d; color:#fff; }
.btn-danger:hover { background:#d4380d; }
.btn-success { background:#52c41a; color:#fff; }
.btn-success:hover { background:#389e0d; }
.btn-sm { padding:5px 12px; font-size:12px; }
.filters { display:flex; gap:10px; margin-bottom:15px; flex-wrap:wrap; align-items:center; }
.filters select, .filters input { border:1px solid #ddd; border-radius:8px; padding:8px 12px; font-size:14px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:#fafafa; padding:10px; text-align:left; border-bottom:2px solid #f0f0f0; white-space:nowrap; }
td { padding:10px; border-bottom:1px solid#f0f0f0; }
tr:hover { background:#fafafa; }
.tag { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:500; }
.tag-unused { background:#e6f7ff; color:#1890ff; }
.tag-activated { background:#f6ffed; color:#52c41a; }
.tag-banned { background:#fff1f0; color:#f5222d; }
.tag-expired { background:#fff7e6; color:#fa8c16; }
.pagination { display:flex; gap:5px; justify-content:center; margin-top:15px; }
.pagination button { border:1px solid #ddd; background:#fff; border-radius:6px; padding:6px 12px; cursor:pointer; font-size:13px; }
.pagination button.active { background:#667eea; color:#fff; border-color:#667eea; }
.pagination button:disabled { opacity:0.4; cursor:not-allowed; }
.modal-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); display:none; justify-content:center; align-items:center; z-index:999; }
.modal-overlay.show { display:flex; }
.modal { background:#fff; border-radius:12px; padding:30px; max-width:500px; width:90%; max-height:80vh; overflow-y:auto; }
.modal h2 { margin-bottom:15px; }
.modal .card-list { background:#f5f5f5; border-radius:8px; padding:15px; margin:10px 0; font-family:monospace; font-size:14px; line-height:2; }
.modal .copy-btn { margin-top:10px; }
.login-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:linear-gradient(135deg,#667eea,#764ba2); display:flex; justify-content:center; align-items:center; z-index:1000; }
.login-box { background:#fff; border-radius:16px; padding:40px; width:350px; text-align:center; }
.login-box h2 { margin-bottom:20px; color:#333; }
.login-box input { width:100%; border:1px solid #ddd; border-radius:8px; padding:12px; font-size:14px; margin-bottom:15px; }
.login-box .btn { width:100%; }
.toast { position:fixed; top:20px; right:20px; background:#333; color:#fff; padding:12px 24px; border-radius:8px; z-index:9999; opacity:0; transition:opacity 0.3s; }
.toast.show { opacity:1; }
.toast.success { background:#52c41a; }
.toast.error { background:#f5222d; }
</style>
</head>
<body>

<!-- 登录页 -->
<div class="login-overlay" id="loginOverlay">
  <div class="login-box">
    <h2>EN启动 管理后台</h2>
    <input type="password" id="adminTokenInput" placeholder="请输入管理Token" onkeydown="if(event.key==='Enter')doLogin()">
    <button class="btn btn-primary" onclick="doLogin()">登录</button>
  </div>
</div>

<!-- 主界面 -->
<div id="mainContent" style="display:none;">
  <div class="header">
    <h1>EN启动 - 卡密管理后台</h1>
    <span class="user">Token: <span id="tokenDisplay"></span></span>
  </div>

  <div class="container">
    <!-- 统计卡片 -->
    <div class="stats-grid">
      <div class="stat-card blue"><div class="num" id="statTotal">0</div><div class="label">总卡密数</div></div>
      <div class="stat-card green"><div class="num" id="statUnused">0</div><div class="label">未激活</div></div>
      <div class="stat-card orange"><div class="num" id="statActivated">0</div><div class="label">已激活</div></div>
      <div class="stat-card red"><div class="num" id="statBanned">0</div><div class="label">已封禁</div></div>
    </div>

    <!-- 生成卡密 -->
    <div class="panel">
      <div class="panel-title">生成卡密</div>
      <div class="gen-form">
        <div class="field">
          <label>数量</label>
          <input type="number" id="genCount" value="1" min="1" max="1000">
        </div>
        <div class="field">
          <label>有效天数</label>
          <input type="number" id="genDays" value="30" min="1" max="3650">
        </div>
        <button class="btn btn-primary" onclick="generateCards()">生成</button>
      </div>
    </div>

    <!-- 卡密池文件上传 -->
    <div class="panel">
      <div class="panel-title">卡密池（上传卡密.txt，APP端自动下拉）</div>
      <div class="gen-form" style="margin-bottom:15px;">
        <div class="field">
          <label>选择卡密文件（.txt，每行一个卡密）</label>
          <input type="file" id="kamiFile" accept=".txt,text/plain" style="font-size:12px;">
        </div>
        <button class="btn btn-primary" onclick="uploadKamiFile()">上传</button>
        <button class="btn btn-success btn-sm" onclick="loadKamiPool()">刷新</button>
        <button class="btn btn-danger btn-sm" onclick="clearKamiPool()">清空卡密池</button>
      </div>
      <div id="kamiPoolStats" style="padding:15px;background:#f5f5f5;border-radius:8px;text-align:center;color:#666;">加载中...</div>







    </div>

    <!-- 卡密列表 -->
    <div class="panel">
      <div class="panel-title">卡密列表</div>
      <div class="filters">
        <select id="filterStatus" onchange="loadCards()">
          <option value="">全部状态</option>
          <option value="unused">未激活</option>
          <option value="activated">已激活</option>
        </select>
        <input type="text" id="searchKey" placeholder="搜索卡密..." oninput="loadCards()">
        <button class="btn btn-primary btn-sm" onclick="loadCards()">刷新</button>
        <button class="btn btn-success btn-sm" onclick="exportCards()">导出CSV</button>
        <button class="btn btn-danger btn-sm" onclick="deleteAllUnused()">清空未激活</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>卡密</th>
            <th>状态</th>
            <th>设备信息</th>
            <th>激活时间</th>
            <th>到期时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="cardTableBody">
          <tr><td colspan="7" style="text-align:center;color:#999;padding:30px;">加载中...</td></tr>
        </tbody>
      </table>
      <div class="pagination" id="pagination"></div>
    </div>

    <!-- SO文件云更新管理 -->
    <div class="panel">
      <div class="panel-title">SO文件云更新</div>
      <div class="gen-form" style="margin-bottom:15px;">
        <div class="field">
          <label>版本号</label>
          <input type="text" id="soVersion" placeholder="如 1.0.0" style="width:120px;">
        </div>
        <div class="field">
          <label>更新说明</label>
          <input type="text" id="soDesc" placeholder="本次更新内容" style="width:250px;">
        </div>
        <div class="field">
          <label>强制更新</label>
          <select id="soForce" style="padding:8px;border-radius:8px;border:1px solid #ddd;">
            <option value="0">否</option>
            <option value="1">是</option>
          </select>
        </div>
        <div class="field">
          <label>选择.so文件</label>
          <input type="file" id="soFile" accept=".so" style="font-size:12px;">
        </div>
        <button class="btn btn-primary" onclick="uploadSo()">上传</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>版本</th>
            <th>文件名</th>
            <th>大小</th>
            <th>MD5</th>
            <th>强制更新</th>
            <th>更新说明</th>
            <th>上传时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="soTableBody">
          <tr><td colspan="9" style="text-align:center;color:#999;padding:20px;">加载中...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 卡密版本分配 -->
    <div class="panel">
      <div class="panel-title">卡密版本分配</div>
      <div class="gen-form" style="margin-bottom:15px;">
        <div class="field">
          <label>卡密</label>
          <input type="text" id="assignCardKey" placeholder="EN-XXXX-XXXX-XXXX-XXXX" style="width:220px;">
        </div>
        <div class="field">
          <label>指定版本</label>
          <select id="assignVersion" style="padding:8px;border-radius:8px;border:1px solid #ddd;width:140px;">
            <option value="">选择版本</option>
          </select>
        </div>
        <button class="btn btn-primary" onclick="assignVersion()">分配</button>
        <button class="btn btn-success btn-sm" onclick="loadAssignList()">刷新</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>卡密</th>
            <th>指定版本</th>
            <th>分配时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="assignTableBody">
          <tr><td colspan="4" style="text-align:center;color:#999;padding:20px;">加载中...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 林宇模块管理 -->
    <div class="panel">
      <div class="panel-title">林宇模块管理</div>
      <div class="gen-form" style="margin-bottom:15px;">
        <div class="field">
          <label>通道</label>
          <select id="linyuChannel" style="padding:8px;border-radius:8px;border:1px solid #ddd;width:120px;">
            <option value="1">过验证</option>
            <option value="2">驱动</option>
            <option value="3">内核</option>
          </select>
        </div>
        <div class="field">
          <label>版本号</label>
          <input type="text" id="linyuVersion" placeholder="如 1.0.0" style="width:120px;">
        </div>
        <div class="field">
          <label>选择文件</label>
          <input type="file" id="linyuFile" style="font-size:12px;">
        </div>
        <button class="btn btn-primary" onclick="uploadLinyu()">上传</button>
        <button class="btn btn-success btn-sm" onclick="loadLinyuList()">刷新</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>通道</th>
            <th>版本</th>
            <th>文件名</th>
            <th>大小</th>
            <th>MD5</th>
            <th>上传时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="linyuTableBody">
          <tr><td colspan="8" style="text-align:center;color:#999;padding:20px;">加载中...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- 生成结果弹窗 -->
<div class="modal-overlay" id="genModal">
  <div class="modal">
    <h2>生成成功</h2>
    <p>以下为新生成的卡密：</p>
    <div class="card-list" id="genResult"></div>
    <button class="btn btn-primary copy-btn" onclick="copyGenerated()">复制全部</button>
    <button class="btn btn-success" style="margin-left:8px;" onclick="document.getElementById('genModal').classList.remove('show')">关闭</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let adminToken = localStorage.getItem('adminToken') || '';
let currentPage = 1;
const perPage = 20;

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (type || '');
  setTimeout(() => t.classList.remove('show'), 3000);
}

function api(url, method, data) {
  const opts = { method: method || 'GET', headers: { 'Authorization': 'Bearer ' + adminToken, 'Content-Type': 'application/json' } };
  if (data) opts.body = JSON.stringify(data);
  return fetch(url, opts).then(r => r.json());
}

function doLogin() {
  adminToken = document.getElementById('adminTokenInput').value.trim();
  if (!adminToken) { showToast('请输入Token', 'error'); return; }
  api('/api/admin/stats').then(r => {
    if (r.success) {
      localStorage.setItem('adminToken', adminToken);
      document.getElementById('loginOverlay').style.display = 'none';
      document.getElementById('mainContent').style.display = 'block';
      document.getElementById('tokenDisplay').textContent = adminToken.substring(0,8) + '...';
      loadStats();
      loadCards();
      loadKamiPool();
    } else {
      showToast('Token错误', 'error');
    }
  }).catch(() => showToast('连接失败', 'error'));
}

function loadStats() {
  api('/api/admin/stats').then(r => {
    if (r.success) {
      document.getElementById('statTotal').textContent = r.stats.total;
      document.getElementById('statUnused').textContent = r.stats.unused;
      document.getElementById('statActivated').textContent = r.stats.activated;
      document.getElementById('statBanned').textContent = r.stats.banned;
    }
  });
}

function generateCards() {
  const count = parseInt(document.getElementById('genCount').value) || 1;
  const days = parseInt(document.getElementById('genDays').value) || 30;
  if (count < 1 || count > 1000) { showToast('数量1-1000', 'error'); return; }
  api('/api/admin/generate', 'POST', { count, expires_days: days }).then(r => {
    if (r.success) {
      showToast('生成' + r.count + '个卡密', 'success');
      document.getElementById('genResult').innerHTML = r.cards.map(c => '<div>'+c+'</div>').join('');
      document.getElementById('genModal').classList.add('show');
      loadStats();
      loadCards();
    } else {
      showToast(r.message || '生成失败', 'error');
    }
  });
}

function copyGenerated() {
  const text = document.getElementById('genResult').innerText;
  navigator.clipboard.writeText(text).then(() => showToast('已复制', 'success'));
}

function loadCards() {
  const status = document.getElementById('filterStatus').value;
  const search = document.getElementById('searchKey').value.trim().toUpperCase();
  let url = '/api/admin/list?page=' + currentPage + '&per_page=' + perPage;
  if (status) url += '&status=' + status;

  api(url).then(r => {
    if (!r.success) return;
    let cards = r.cards;
    if (search) cards = cards.filter(c => c.card_key.includes(search));

    let now = new Date();
    let html = cards.map(c => {
      let statusTag;
      if (c.banned) {
        statusTag = '<span class="tag tag-banned">已封禁</span>';
      } else if (c.status === 'unused') {
        statusTag = '<span class="tag tag-unused">未激活</span>';
      } else if (c.expires_at && new Date(c.expires_at.replace(/-/g,'/')) < now) {
        statusTag = '<span class="tag tag-expired">已过期</span>';
      } else {
        statusTag = '<span class="tag tag-activated">已激活</span>';
      }
      const deviceInfo = c.device_info ? c.device_info.split('\\n')[0].replace('Model: ','') : '-';
      const banBtn = c.banned
        ? '<button class="btn btn-success btn-sm" onclick="banCard(\\''+c.card_key+'\\',0)">解封</button>'
        : '<button class="btn btn-danger btn-sm" onclick="banCard(\\''+c.card_key+'\\',1)">封禁</button>';
      const unbindBtn = c.status === 'activated'
        ? '<button class="btn btn-primary btn-sm" onclick="unbindCard(\\''+c.card_key+'\\')">解绑</button>'
        : '';
      const extendBtn = '<button class="btn btn-primary btn-sm" onclick="extendCard(\\''+c.card_key+'\\')">延期</button>';
      const deleteBtn = '<button class="btn btn-danger btn-sm" onclick="deleteCard(\\''+c.card_key+'\\')">删除</button>';
      const copyBtn = '<button class="btn btn-sm" style="background:#e8e8e8;" onclick="copyKey(\\''+c.card_key+'\\')">复制</button>';
      return '<tr>'
        + '<td>'+c.id+'</td>'
        + '<td style="font-family:monospace;font-weight:600;">'+c.card_key+'</td>'
        + '<td>'+statusTag+'</td>'
        + '<td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="'+(c.device_info||'')+'">'+deviceInfo+'</td>'
        + '<td>'+(c.activated_at||'-')+'</td>'
        + '<td>'+(c.expires_at||'-')+'</td>'
        + '<td style="white-space:nowrap;">'+copyBtn+' '+unbindBtn+' '+extendBtn+' '+banBtn+' '+deleteBtn+'</td>'
        + '</tr>';
    }).join('');

    if (cards.length === 0) html = '<tr><td colspan="7" style="text-align:center;color:#999;padding:30px;">暂无数据</td></tr>';
    document.getElementById('cardTableBody').innerHTML = html;

    // 分页
    const totalPages = Math.ceil(r.total / perPage);
    let pHtml = '';
    pHtml += '<button onclick="goPage('+(currentPage-1)+')" '+(currentPage<=1?'disabled':'')+'>上一页</button>';
    for (let i = 1; i <= Math.min(totalPages, 10); i++) {
      pHtml += '<button class="'+(i===currentPage?'active':'')+'" onclick="goPage('+i+')">'+i+'</button>';
    }
    if (totalPages > 10) pHtml += '<button disabled>...</button><button onclick="goPage('+totalPages+')">'+totalPages+'</button>';
    pHtml += '<button onclick="goPage('+(currentPage+1)+')" '+(currentPage>=totalPages?'disabled':'')+'>下一页</button>';
    document.getElementById('pagination').innerHTML = totalPages > 1 ? pHtml : '';
  });
}

function goPage(p) { currentPage = p; loadCards(); }

function banCard(key, ban) {
  const url = ban ? '/api/admin/ban' : '/api/admin/unban';
  if (!confirm(ban ? '确认封禁 '+key+' ?' : '确认解封 '+key+' ?')) return;
  api(url, 'POST', { card_key: key }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) { loadStats(); loadCards(); }
  });
}

function unbindCard(key) {
  if (!confirm('确认解绑 '+key+' 的设备？\\n解绑后卡密恢复为未激活状态，可重新绑定其他设备。')) return;
  api('/api/admin/unbind', 'POST', { card_key: key }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) { loadStats(); loadCards(); }
  });
}

function extendCard(key) {
  const days = prompt('为 '+key+' 延期多少天？', '30');
  if (days === null) return;
  const addDays = parseInt(days);
  if (!addDays || addDays < 1) { showToast('请输入有效天数', 'error'); return; }
  api('/api/admin/extend', 'POST', { card_key: key, add_days: addDays }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) loadCards();
  });
}

function deleteCard(key) {
  if (!confirm('确认删除 '+key+' ?\\n删除后不可恢复！')) return;
  api('/api/admin/delete', 'POST', { card_key: key }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) { loadStats(); loadCards(); }
  });
}

function copyKey(key) {
  navigator.clipboard.writeText(key).then(() => showToast('已复制: ' + key, 'success'));
}

function exportCards() {
  const status = document.getElementById('filterStatus').value;
  window.open('/api/admin/export?format=csv' + (status ? '&status=' + status : '') + '&t=' + adminToken, '_blank');
}

function deleteAllUnused() {
  if (!confirm('确认删除所有未激活的卡密？\\n此操作不可恢复！')) return;
  api('/api/admin/list?status=unused&per_page=1000').then(r => {
    if (!r.success || r.cards.length === 0) { showToast('没有未激活卡密', 'error'); return; }
    let count = 0;
    let promises = r.cards.map(c => api('/api/admin/delete', 'POST', { card_key: c.card_key }).then(() => count++));
    Promise.all(promises).then(() => {
      showToast('已删除 ' + count + ' 个未激活卡密', 'success');
      loadStats(); loadCards();
    });
  });
}

// ============ 卡密池管理 ============

function uploadKamiFile() {
  const fileInput = document.getElementById('kamiFile');
  if (!fileInput.files[0]) { showToast('请选择卡密.txt文件', 'error'); return; }
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  showToast('上传中...', '');
  fetch('/api/admin/kami/upload', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + adminToken },
    body: formData
  }).then(r => r.json()).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) { document.getElementById('kamiFile').value = ''; loadKamiPool(); loadStats(); }
  }).catch(() => showToast('上传失败', 'error'));
}

function loadKamiPool() {
  api('/api/admin/kami/pool/list').then(r => {
    if (!r.success) return;
    const count = r.count || 0;
    const el = document.getElementById('kamiPoolStats');
    if (count === 0) {
      el.innerHTML = '<span style="color:#999;">卡密池为空，请上传卡密.txt</span>';
    } else {
      el.innerHTML = '<span style="color:#4CAF50;font-weight:600;font-size:18px;">' + count + '</span> <span style="color:#666;">个卡密（已隐藏详情）</span>';
    }
  });
}

function clearKamiPool() {
  if (!confirm('确认清空卡密池？\\nAPP端下拉将不再显示卡密（不影响已生成的卡密记录）。')) return;
  api('/api/admin/kami/pool/clear', 'POST').then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) loadKamiPool();
  });
}
function uploadSo() {
  const fileInput = document.getElementById('soFile');
  const version = document.getElementById('soVersion').value.trim();
  const desc = document.getElementById('soDesc').value.trim();
  const force = document.getElementById('soForce').value;

  if (!fileInput.files[0]) { showToast('请选择.so文件', 'error'); return; }
  if (!version) { showToast('请填写版本号', 'error'); return; }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('version', version);
  formData.append('description', desc);
  formData.append('force_update', force);

  showToast('上传中...', '');
  fetch('/api/admin/so/upload', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + adminToken },
    body: formData
  }).then(r => r.json()).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) {
      document.getElementById('soVersion').value = '';
      document.getElementById('soDesc').value = '';
      document.getElementById('soFile').value = '';
      loadSoList();
    }
  }).catch(() => showToast('上传失败', 'error'));
}

function loadSoList() {
  api('/api/admin/so/list').then(r => {
    if (!r.success) return;
    let html = r.updates.map(u => {
      const sizeKB = (u.file_size / 1024).toFixed(1) + ' KB';
      const forceTag = u.force_update ? '<span class="tag tag-banned">强制</span>' : '<span class="tag tag-unused">普通</span>';
      const md5Short = u.md5sum.substring(0, 12) + '...';
      return '<tr>'
        + '<td>'+u.id+'</td>'
        + '<td style="font-weight:600;">v'+u.version+'</td>'
        + '<td style="font-family:monospace;">'+u.filename+'</td>'
        + '<td>'+sizeKB+'</td>'
        + '<td style="font-family:monospace;font-size:11px;" title="'+u.md5sum+'">'+md5Short+'</td>'
        + '<td>'+forceTag+'</td>'
        + '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="'+(u.description||'')+'">'+(u.description||'-')+'</td>'
        + '<td style="font-size:12px;">'+u.created_at+'</td>'
        + '<td><button class="btn btn-danger btn-sm" onclick="deleteSo('+u.id+',\\''+u.version+'\\')">删除</button></td>'
        + '</tr>';
    }).join('');
    if (r.updates.length === 0) html = '<tr><td colspan="9" style="text-align:center;color:#999;padding:20px;">暂无更新，请上传.so文件</td></tr>';
    document.getElementById('soTableBody').innerHTML = html;
  });
}

function deleteSo(id, ver) {
  if (!confirm('确认删除 v'+ver+' ?')) return;
  api('/api/admin/so/delete', 'POST', { id: id }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) { loadSoList(); loadVersions(); }
  });
}

// ============ 卡密版本分配 ============

function loadVersions() {
  api('/api/admin/so/versions').then(r => {
    if (!r.success) return;
    const sel = document.getElementById('assignVersion');
    sel.innerHTML = '<option value="">选择版本</option>' + r.versions.map(v => '<option value="'+v+'">v'+v+'</option>').join('');
  });
}

function assignVersion() {
  const cardKey = document.getElementById('assignCardKey').value.trim().toUpperCase();
  const version = document.getElementById('assignVersion').value;
  if (!cardKey) { showToast('请输入卡密', 'error'); return; }
  if (!version) { showToast('请选择版本', 'error'); return; }
  api('/api/admin/so/assign', 'POST', { card_key: cardKey, version: version }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) { document.getElementById('assignCardKey').value = ''; loadAssignList(); }
  });
}

function loadAssignList() {
  api('/api/admin/so/assign/list').then(r => {
    if (!r.success) return;
    let html = r.assigns.map(a => {
      return '<tr>'
        + '<td style="font-family:monospace;font-weight:600;">'+a.card_key+'</td>'
        + '<td style="font-weight:600;">v'+a.version+'</td>'
        + '<td>'+a.assigned_at+'</td>'
        + '<td><button class="btn btn-danger btn-sm" onclick="deleteAssign(\\''+a.card_key+'\\')">取消分配</button></td>'
        + '</tr>';
    }).join('');
    if (r.assigns.length === 0) html = '<tr><td colspan="4" style="text-align:center;color:#999;padding:20px;">暂无分配，未分配的卡密将使用最新版本</td></tr>';
    document.getElementById('assignTableBody').innerHTML = html;
  });
}

function deleteAssign(key) {
  if (!confirm('确认取消 '+key+' 的版本指定？\\n取消后将使用最新版本。')) return;
  api('/api/admin/so/assign/delete', 'POST', { card_key: key }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) loadAssignList();
  });
}

function uploadLinyu() {
  const fileInput = document.getElementById('linyuFile');
  const channel = document.getElementById('linyuChannel').value;
  const version = document.getElementById('linyuVersion').value.trim();

  if (!fileInput.files[0]) { showToast('请选择文件', 'error'); return; }
  if (!version) { showToast('请填写版本号', 'error'); return; }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('channel', channel);
  formData.append('version', version);

  showToast('上传中...', '');
  fetch('/api/admin/linyu/upload', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + adminToken },
    body: formData
  }).then(r => r.json()).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) {
      document.getElementById('linyuVersion').value = '';
      document.getElementById('linyuFile').value = '';
      loadLinyuList();
    }
  }).catch(() => showToast('上传失败', 'error'));
}

function loadLinyuList() {
  api('/api/admin/linyu/list').then(r => {
    if (!r.success) return;
    const channelNames = {1: '过验证', 2: '驱动', 3: '内核'};
    let html = r.files.map(f => {
      const sizeKB = (f.file_size / 1024).toFixed(1) + ' KB';
      const chName = channelNames[f.channel] || f.channel;
      const md5Short = f.md5sum.substring(0, 12) + '...';
      return '<tr>'
        + '<td>'+f.id+'</td>'
        + '<td><span class="tag tag-unused">'+chName+'</span></td>'
        + '<td style="font-weight:600;">v'+f.version+'</td>'
        + '<td style="font-family:monospace;">'+f.filename+'</td>'
        + '<td>'+sizeKB+'</td>'
        + '<td style="font-family:monospace;font-size:11px;" title="'+f.md5sum+'">'+md5Short+'</td>'
        + '<td style="font-size:12px;">'+f.created_at+'</td>'
        + '<td><button class="btn btn-danger btn-sm" onclick="deleteLinyu('+f.id+')">删除</button></td>'
        + '</tr>';
    }).join('');
    if (r.files.length === 0) html = '<tr><td colspan="8" style="text-align:center;color:#999;padding:20px;">暂无文件，请上传</td></tr>';
    document.getElementById('linyuTableBody').innerHTML = html;
  });
}

function deleteLinyu(id) {
  if (!confirm('确认删除此文件？')) return;
  api('/api/admin/linyu/delete', 'POST', { id: id }).then(r => {
    showToast(r.message, r.success ? 'success' : 'error');
    if (r.success) loadLinyuList();
  });
}

// 自动登录
if (adminToken) {
  api('/api/admin/stats').then(r => {
    if (r.success) {
      document.getElementById('loginOverlay').style.display = 'none';
      document.getElementById('mainContent').style.display = 'block';
      document.getElementById('tokenDisplay').textContent = adminToken.substring(0,8) + '...';
      loadStats();
      loadCards();
      loadKamiPool();
      loadSoList();
      loadVersions();
      loadAssignList();
      loadLinyuList();
    }
  });
}
</script>
</body>
</html>
'''


@app.route('/admin')
def admin_page():
    """Web管理后台页面"""
    return render_template_string(ADMIN_PAGE_HTML)


if __name__ == '__main__':
    print("=" * 50)
    print("  EN启动 - 卡密系统服务器")
    print("=" * 50)
    init_keys()
    init_db()
    print(f"[*] 数据库: {DB_PATH}")
    print(f"[*] 密钥目录: {KEY_DIR}")
    print(f"[*] 管理Token: {ADMIN_TOKEN}")
    print(f"[*] 服务启动: http://0.0.0.0:5000")
    print("=" * 50)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
