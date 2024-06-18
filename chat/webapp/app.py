# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash, make_response
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
from os import urandom
from PIL import Image, ImageDraw, ImageFont
import requests
import hashlib
import pyotp
import datetime
import base64
import bcrypt

app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)
publicKey = {}


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)


@app.route('/push_public_key', methods=['POST'])
def register_public_key():
    data = request.json
    posterID = data['posterID']
    publicKey[f"User{posterID}PK"] = data['publicKey']
    print(f"User{posterID}PK:", publicKey[f"User{posterID}PK"])
    return jsonify({'message': 'Public key registered successfully'}), 200
    # return f"{session}", 200


@app.route('/pull_public_key/<peer_id>', methods=['GET'])
def get_public_key(peer_id):
    public_key = publicKey.get(f"User{peer_id}PK")
    print(f"Data retreived for {peer_id}: ", public_key)
    if public_key:
        return jsonify({'publicKey': public_key})
    else:
        return jsonify({'message': 'Public key not found'}), 404


@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}


@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)

    cur = mysql.connection.cursor()
    query = """SELECT * FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]
    cur.close()

    return jsonify({'messages': messages})


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        error=check_login(request.form)
        if error=='success':
          return redirect(url_for('index'))
    code = generate_captcha()
    create_captcha_image(code)
    resp = make_response(render_template('login.html',error=error))
    resp.set_cookie('captcha', code)
    return resp


@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'ciphertext' in request.json or not 'iv' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['ciphertext']
    iv = request.json['iv']
    tag = request.json['tag']

    save_message(sender_id, receiver_id, message_text, iv, tag)

    return jsonify({'status': 'success', 'message': 'Message sent'}), 200


def save_message(sender, receiver, ciphertext, iv, tag, second_tag=None):
    cur = mysql.connection.cursor()
    if second_tag is None:
        cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text,iv,tag) VALUES (%s, %s, %s, %s, %s)",
                    (sender, receiver, ciphertext, iv, tag))
    else:
        cur.execute(
            "INSERT INTO messages (sender_id, receiver_id, message_text,iv,tag, second_tag) "
            "VALUES (%s, %s, %s, %s, %s, %s)", (sender, receiver, ciphertext, iv, tag, second_tag))
    mysql.connection.commit()
    cur.close()


@app.route('/refreshKey', methods=['POST'])
def refreshKey():
    if 'user_id' not in session:
        abort(403)

    if not request.json or not ('iv' in request.json and 'tag' in request.json and 'second_tag' in request.json):
        abort(400)

    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['ciphertext']
    iv = request.json['iv']
    tag = request.json['tag']
    second_tag = request.json['second_tag']

    save_message(sender_id, receiver_id, message_text, iv, tag, second_tag)

    print("Server received a request for refreshKey")
    return jsonify({'status': 'success', 'message': 'Keys changed'}), 200


@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))


def random_integer(min_value, max_value):
    range_width = max_value - min_value
    random_bytes = urandom(4)
    random_int = int.from_bytes(random_bytes, 'big')
    return min_value + (random_int % range_width)


def generate_captcha():
    code = ''
    vocabulary = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    for _ in range(4):
        i = random_integer(0, len(vocabulary))
        code += vocabulary[i]
    return code


def draw_random_line(draw, width, height):
    start = (random_integer(0, width), random_integer(0, height))
    end = (random_integer(0, width), random_integer(0, height))
    color = (random_integer(0, 255), random_integer(0, 255), random_integer(0, 255))
    draw.line([start, end], fill=color, width=2)


def create_captcha_image(code):
    image = Image.new('RGB', (200, 100), color=(255, 255, 255))
    font = ImageFont.truetype('DejaVuSans.ttf', 40)
    d = ImageDraw.Draw(image)
    d.text((40, 30), code, fill=(0, 0, 0), font=font)
    for _ in range(10):
        draw_random_line(d, image.width, image.height)
    image.save('static/captcha.png')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password'].encode('utf-8')
        recoverykey = request.json['recoverykey']
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()) # bcrypt
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
        account = cur.fetchone()
        if not account:
            if len(password) < 8:
                return jsonify({'status': 'error', 'message': 'Register Failed: The password should be longer than 8 letters'}), 200
            if check_password(password):
                b32_password = base64.b32encode(password).decode()
                qrcode = pyotp.totp.TOTP(b32_password).provisioning_uri(name=username, issuer_name='WebApp')
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO users (username, password,recoverykey,ratelimit) VALUES (%s, %s, %s, %s)",
                            (username, hashed_password, recoverykey, 0))
                mysql.connection.commit()
                return jsonify({'status': 'success', 'message': 'Register Successed', "data": qrcode}), 200
            else:
                return jsonify({'status': 'error', 'message': 'Register Failed: The password has been leaked'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'User has registered'}), 200
    return jsonify({'status': 'success', 'message': 'Register Successed'}), 200


def check_password(password):
    if len(password) < 8:
        return False
    sha1_password = hashlib.sha1(password).hexdigest().upper()

    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    api_url = f"https://api.pwnedpasswords.com/range/{prefix}"

    response = requests.get(api_url)

    if response.status_code == 200:
        hashes = response.text.splitlines()

        for h in hashes:
            if suffix in h:
                return False
        return True

    else:
        raise Exception("Failed to check password against API.")


def check_login(userDetails):
    username = userDetails['username']
    password = userDetails['password'].encode('utf-8')
    secondpassword = userDetails['secondpassword']
    method = userDetails['method']
    captcha = userDetails['captcha']
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id,password,limitTime,ratelimit,recoverykey FROM users WHERE username=%s",
                (username,))
    account = cur.fetchone()
    if account[3] >= 5:
        lockuser(username)
        return 'User is been locked'
    if account is None:
        return 'Invalid Username'
    if captcha.lower() != request.cookies.get('captcha').lower():
        error_password(username)
        return 'Invalid Captcha'

    if account[2] is not None and account[2] > datetime.datetime.now():
        return 'User is been locked'

    if not bcrypt.checkpw(password,account[1].encode('utf-8')):
        error_password(username)
        return 'Invalid Password'

    if method == '0':
        b32_password = base64.b32encode(password).decode()
        totp = pyotp.TOTP(b32_password)
        result = totp.verify(secondpassword)
        if not result:
            error_password(username)
            return 'Invalid Second Password'

    else:
        if account[4] != secondpassword:
            error_password(username)
            return 'Invalid Second Password'

    session['username'] = username
    session['user_id'] = account[0]
    return 'success'


def lockuser(username):
    limit_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET limitTime=%s,ratelimit=0 WHERE username=%s", (limit_time, username,))
    mysql.connection.commit()


def error_password(username):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET ratelimit=ratelimit+1 WHERE username=%s", (username,))
    mysql.connection.commit()


if __name__ == '__main__':
    app.run(debug=True)
