from sqlalchemy import exists
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, session, render_template
from db import Record, User
from db import session as dbsess
from registry import *
from config import *
from verify import *
from ip import *
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = HASH_KEY


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/submit')
def submit():
    return render_template('submit.html')


@app.route('/api/login')
def api_login():
    asn = request.args['asn']
    password = request.args['password']
    query = dbsess.query(User).filter(User.as_num == asn).first()
    if query is None:
        return {
            'status': 403,
            'text': '密码错误或查无此人'
        }
    if check_password_hash(query.password, password):
        session['user_asn'] = asn
        session['user_id'] = query.id
        return {
            'status': 200,
            'text': 'success'
        }
    else:
        return {
            'status': 403,
            'text': '密码错误或查无此人'
        }


@app.route('/api/registry_data')
def registry_data():
    asn = request.args['asn'].strip()
    try:
        _, maintainer, source = get_maintainer(asn)
    except InvalidASNorIP:
        return {
            'status': 403,
            'text': 'Invalid ASN'
        }
    auth = get_auth_key(maintainer)
    plain_text = base64.b64encode(os.urandom(44)).decode()
    session['plain'] = plain_text
    session['asn'] = asn
    session['source'] = source
    return {
        'status': 200,
        'maintainer': maintainer,
        'source': source,
        'asn': asn,
        'auth': [{
            'method': item[0],
            'info': item[1],
            'show': item[1].split()[-1]
        } for item in auth],
        'plaintext': plain_text
    }


@app.route('/api/register', methods=['POST'])
def reg():
    plain_text = session['plain']
    asn = session['asn']
    sign = request.form['sign']
    auth_index = int(request.form['auth'])
    password = request.form['password']
    _, maintainer, source = get_maintainer(asn)
    method, fingerprint = get_auth_key(maintainer)[auth_index]
    if method == 'pgp-fingerprint' or method == 'PGPKEY':
        pubkey = request.form['pubkey']
    elif method == 'ssh-rsa' or method == 'ssh-ed25519':
        pubkey = None
        fingerprint = method + ' ' + fingerprint
    else:
        return {
            'status': 403,
            'text': 'Method unavailable.'
        }
    try:
        verify_signature(plain_text, fingerprint, pubkey, sign, method)
        if dbsess.query(exists().where(User.as_num == asn)).scalar():
            return {
                'status': 403,
                'text': 'User exists'
            }
        dbsess.add(User(
            as_num=asn,
            password=generate_password_hash(password)
        ))
        dbsess.commit()
        session.clear()
        return {
            'status': 200,
            'text': 'success'
        }
    except ValueError as e:
        return {
            'status': 403,
            'text': e.args
        }


@app.route('/api/query')
def api_query():
    ip = ''
    if 'ip' in request.args:
        ip = request.args['ip'].strip()
    if ip == '':
        ip = request.remote_addr
    type = ip_type(ip)
    if type == 'unknown':
        return {
            'status': 403,
            'text': 'Unknown IP address'
        }
    try:
        ip_int = ip2int(ip)
    except ValueError:
        return {
            'status': 403,
            'text': 'Unknown IP address'
        }
    query = dbsess.query(Record).filter(Record.type == (4 if type == 'ipv4' else 6), Record.start_addr <= ip_int, Record.end_addr >= ip_int).all()
    data = [{
        'ip': ip,
        'type': 'IPv4' if item.type == 4 else 'IPv6',
        'cidr': item.cidr,
        'count': int(item.end_addr - item.start_addr + 1),
        'asn': item.as_num,
        'location': item.location,
        'country': item.country,
        'geo_x': item.geo_x,
        'geo_y': item.geo_y,
        'provider': item.provider,
        'idc': item.idc,
        'usage': item.usage,
        'is_pop': item.pop
    } for item in query]
    data.sort(key=lambda x: x['count'])
    return {
        'status': 200,
        'ip': ip,
        'data': data
    }


@app.route('/api/submit')
def api_submit():
    cidr = request.args['cidr']
    if dbsess.query(exists().where(Record.cidr == cidr)).scalar():
        return {
            'status': 403,
            'text': 'CIDR exists, delete the record first.'
        }
    user_start, user_end = ip_range(cidr)
    try:
        whois_cidr, whois_asn = get_cidr(user_start)
    except InvalidASNorIP:
        return {
            'status': 403,
            'text': 'CIDR not found.'
        }
    whois_start, whois_end = ip_range(whois_cidr)
    asn = session['user_asn']
    if asn not in whois_asn:
        return {
            'status': 403,
            'text': 'Maintainer does not match.'
        }
    if ip2int(whois_end) < ip2int(user_end):
        return {
            'status': 403,
            'text': 'CIDR too large.'
        }
    dbsess.add(Record(
        logo=request.args['logo'],
        type=4 if ip_type(user_start) == 'ipv4' else 6,
        cidr=cidr,
        start_addr=ip2int(user_start),
        end_addr=ip2int(user_end),
        as_num=asn,
        location=request.args['location'],
        country=request.args['country'],
        geo_x=float(request.args['geo_x']),
        geo_y=float(request.args['geo_y']),
        provider=request.args['provider'],
        idc=request.args['idc'],
        usage=request.args['usage'],
        pop=request.args['pop'] == 'pop',
        creator=session['user_id'],
    ))
    dbsess.commit()
    return {
        'status': 200,
        'text': 'success'
    }


@app.route('/api/delete')
def api_delete():
    cidr = request.args['cidr']
    query = dbsess.query(Record).filter(Record.cidr == cidr).first()
    if query is None:
        return {
            'status': 403,
            'text': 'CIDR not found.'
        }
    user_start, user_end = ip_range(cidr)
    whois_cidr, whois_asn = get_cidr(user_start)
    asn = session['user_asn']
    if asn not in whois_asn:
        return {
            'status': 403,
            'text': 'Maintainer does not match.'
        }
    dbsess.delete(query)
    dbsess.commit()
    return {
        'status': 200,
        'text': 'success'
    }


if __name__ == '__main__':
    app.run(debug=True, host='::')
