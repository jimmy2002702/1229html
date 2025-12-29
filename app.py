from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
CORS(app)

DB_HOST = "localhost"
DB_USER = "owner"
DB_PASSWORD = "123456"
DB_NAME = "user"


def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def get_user_token(token):
    if not token:
        return None
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, level, ban FROM member WHERE auth_token = %s", (token)
            )
            user = cursor.fetchone()
            if user and user["ban"] =="1":
                return None

            return user
    finally:
        conn.close()


def get_current_user_from_request():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        token = None
    user = get_user_token(token)
    return user


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "卻少username or password"}), 400
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM member WHERE username = %s", (username))
            exist = cursor.fetchone()
            if exist:
                return jsonify({"message": "帳號已經存在!"}), 400
            password_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO member(username, password_hash) VALUES(%s , %s)",
                (username, password_hash),
            )
            conn.commit()
        return jsonify({"message": "register ok!"})
    finally:
        conn.close()


@app.route("/api/checkuni", methods=["POST"])
def checkuni():
    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"message": "必須要確認帳號是否已存在!"}), 400
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM member WHERE username = %s",
                (username),
            )
            exist = cursor.fetchone()
            if exist:
                return jsonify({"message": "帳號已經有人使用!", "status": False}), 200
            else:
                return jsonify({"message": "帳號可以使用!", "status": True}), 200
    finally:
        conn.close()


@app.route("/api/login", methods=["POST"])
def loin():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "缺少 username or password"})
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, username, password_hash, level, ban FROM member WHERE username = %s",
                (username),
            )
            user = cursor.fetchone()

            if not user:
                return jsonify({"message": "帳號or密碼錯誤!", "status": False}), 200
            if user["ban"] == "1":
                return jsonify({"message": "已被禁用","status":False}),200
            if not check_password_hash(user["password_hash"], password):
                return jsonify({"message": "帳號or密碼錯誤!", "status": False}), 200
            token = secrets.token_hex(16)
            cursor.execute(
                "UPDATE member SET auth_token = %s WHERE id = %s", (token, user["id"])
            )
            conn.commit()

            return (
                jsonify(
                    {
                        "message": "登陸成功",
                        "username": user["username"],
                        "level": user["level"],
                        "status": True,
                        "token": token,
                    }
                ),
                200,
            )
    finally:
        conn.close()


@app.route("/api/me", methods=["GET"])
def me():
    user = get_current_user_from_request()
    if not user:
        return jsonify({"error": "未登入 or token 無效"}), 401
    return jsonify(
        {
            "username": user["username"],
            "id": user["id"],
            "level": user["level"],
            "status": True,
        }
    )

@app.route("/api/admin/users", methods=["GET"])
def admin_get_all_users():
    current_user =get_current_user_from_request()
    if not current_user:
        return jsonify({"error":"未登入or token無效"}),401
    if current_user["level"] != 'admin':
        return jsonify({"error":"沒有權限，只有admin可以使用!"}),403
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username, level, created_at,city,edu, ban FROM member ORDER BY id DESC")
        users = cursor.fetchall()

        return jsonify({"message":"ok","users":users}),200
    finally:
        conn.close()


@app.route("/api/admin/ban", methods=["PATCH"])
def update_ban():
    user = get_current_user_from_request()
    if not user:
        return jsonify({"message":"未登入"}),401
    if user["level"] != "admin":
        return jsonify({"message":"權限不足"}),403
    data = request.get_json()
    ban = data.get("ban")
    id = data.get("id")
    if id is None or ban is None:
        return jsonify({"error":"id or ban error"}),400
    conn=get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE member SET ban =%s WHERE id = %s",(ban,id))  
            conn.commit()
        return jsonify({"message":"ban 已更新"})      
    finally:
        conn.close()

@app.route("/api/admin/level", methods=["GET"])
def admin_level():
    #確認有沒有登入(token是否合法)
    current_user =get_current_user_from_request()
    if not current_user:
        return jsonify({"error":"未登入or token無效"}),401
    #確認是否為admin
    if current_user["level"] != 'admin':
        return jsonify({"error":"沒有權限，只有admin可以使用!"}),403
    #列出所有的會員資料
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT level, COUNT(*) as count FROM member GROUP BY level")
            rows = cursor.fetchall()
            #回傳所有的會員資料
            return jsonify({"message":"會員等級資料","data":rows})
    finally:
        conn.close()

@app.route("/api/admin/edu", methods=['GET'])
def admin_edu():
    current_user = get_current_user_from_request()
    if not current_user:
        return jsonify({"error":"未登入or token無效"}),401
    #確認是否為admin
    if current_user["level"] != 'admin':
        return jsonify({"error":"沒有權限，只有admin可以使用!"}),403
    #列出所有的會員資料
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT edu , COUNT(*) as count FROM member GROUP BY edu")
            rows = cursor.fetchall()
            return jsonify({"message":"會員學歷資料", "data":rows})
    finally:
        conn.close()

@app.route("/api/admin/city", methods=['GET'])
def admin_city():
    current_user = get_current_user_from_request()
    if not current_user:
        return jsonify({"error":"未登入or token無效"}),401
    #確認是否為admin
    if current_user["level"] != 'admin':
        return jsonify({"error":"沒有權限，只有admin可以使用!"}),403
    #列出所有的會員資料
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT city, COUNT(*) as count FROM member GROUP BY city")
            rows = cursor.fetchall()
            return jsonify({"message":"會員居住地資料", "data":rows})
    finally:
        conn.close()







if __name__ == "__main__":
    app.run(debug=True)
