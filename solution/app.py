import os
import re
import jwt
import bcrypt
import datetime
import psycopg2
from dotenv import load_dotenv
from flask import Flask, request, jsonify

# from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
# from flask_bcrypt import Bcrypt
# from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
load_dotenv()
try:
    conn = psycopg2.connect(host=os.getenv('POSTGRES_HOST'), database=os.getenv('POSTGRES_DATABASE'),
                            user=os.getenv('POSTGRES_USER'), password=os.getenv('POSTGRES_PASSWORD'),
                            port=os.getenv('POSTGRES_PORT'))
except psycopg2.Error as e:
    print("Ошибка подключения к базе данных:", e)
    exit(0)

# conn.autocommit = True
with conn.cursor() as cursor:  # creating countries table
    cursor.execute('''
CREATE TABLE IF NOT EXISTS countries (
    id SERIAL PRIMARY KEY,
    name TEXT,
    alpha2 TEXT,
    alpha3 TEXT,
    region TEXT
  );
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM countries) THEN
        INSERT INTO countries (name, alpha2, alpha3, region) VALUES
          ('Afghanistan','AF','AFG','Asia'),
          ('Åland Islands','AX','ALA','Europe'),
          ('Albania','AL','ALB','Europe'),
          ('Algeria','DZ','DZA','Africa'),
          ('American Samoa','AS','ASM','Oceania'),
          ('Andorra','AD','AND','Europe'),
          ('Angola','AO','AGO','Africa'),
          ('Anguilla','AI','AIA','Americas'),
          ('Antarctica','AQ','ATA',''),
          ('Antigua and Barbuda','AG','ATG','Americas'),
          ('Argentina','AR','ARG','Americas'),
          ('Armenia','AM','ARM','Asia'),
          ('Aruba','AW','ABW','Americas'),
          ('Australia','AU','AUS','Oceania'),
          ('Austria','AT','AUT','Europe'),
          ('Azerbaijan','AZ','AZE','Asia'),
          ('Bahamas','BS','BHS','Americas'),
          ('Bahrain','BH','BHR','Asia'),
          ('Bangladesh','BD','BGD','Asia'),
          ('Barbados','BB','BRB','Americas'),
          ('Belarus','BY','BLR','Europe'),
          ('Belgium','BE','BEL','Europe'),
          ('Belize','BZ','BLZ','Americas'),
          ('Benin','BJ','BEN','Africa'),
          ('Bermuda','BM','BMU','Americas'),
          ('Bhutan','BT','BTN','Asia'),
          ('Bolivia (Plurinational State of)','BO','BOL','Americas'),
          ('Bonaire, Sint Eustatius and Saba','BQ','BES','Americas'),
          ('Bosnia and Herzegovina','BA','BIH','Europe'),
          ('Botswana','BW','BWA','Africa'),
          ('Bouvet Island','BV','BVT','Americas'),
          ('Brazil','BR','BRA','Americas'),
          ('British Indian Ocean Territory','IO','IOT','Africa'),
          ('Brunei Darussalam','BN','BRN','Asia'),
          ('Bulgaria','BG','BGR','Europe'),
          ('Burkina Faso','BF','BFA','Africa'),
          ('Burundi','BI','BDI','Africa'),
          ('Cabo Verde','CV','CPV','Africa'),
          ('Cambodia','KH','KHM','Asia'),
          ('Cameroon','CM','CMR','Africa'),
          ('Canada','CA','CAN','Americas'),
          ('Cayman Islands','KY','CYM','Americas'),
          ('Central African Republic','CF','CAF','Africa'),
          ('Chad','TD','TCD','Africa'),
          ('Chile','CL','CHL','Americas'),
          ('China','CN','CHN','Asia'),
          ('Christmas Island','CX','CXR','Oceania'),
          ('Cocos (Keeling) Islands','CC','CCK','Oceania'),
          ('Colombia','CO','COL','Americas'),
          ('Comoros','KM','COM','Africa'),
          ('Congo','CG','COG','Africa'),
          ('Congo, Democratic Republic of the','CD','COD','Africa'),
          ('Cook Islands','CK','COK','Oceania'),
          ('Costa Rica','CR','CRI','Americas'),
          ('Côte d Ivoire','CI','CIV','Africa'),
          ('Croatia','HR','HRV','Europe'),
          ('Cuba','CU','CUB','Americas'),
          ('Curaçao','CW','CUW','Americas'),
          ('Cyprus','CY','CYP','Asia'),
          ('Czechia','CZ','CZE','Europe'),
          ('Denmark','DK','DNK','Europe'),
          ('Djibouti','DJ','DJI','Africa'),
          ('Dominica','DM','DMA','Americas'),
          ('Dominican Republic','DO','DOM','Americas'),
          ('Ecuador','EC','ECU','Americas'),
          ('Egypt','EG','EGY','Africa'),
          ('El Salvador','SV','SLV','Americas'),
          ('Equatorial Guinea','GQ','GNQ','Africa'),
          ('Eritrea','ER','ERI','Africa'),
          ('Estonia','EE','EST','Europe'),
          ('Eswatini','SZ','SWZ','Africa'),
          ('Ethiopia','ET','ETH','Africa'),
          ('Falkland Islands (Malvinas)','FK','FLK','Americas'),
          ('Faroe Islands','FO','FRO','Europe'),
          ('Fiji','FJ','FJI','Oceania'),
          ('Finland','FI','FIN','Europe'),
          ('France','FR','FRA','Europe'),
          ('French Guiana','GF','GUF','Americas'),
          ('French Polynesia','PF','PYF','Oceania'),
          ('French Southern Territories','TF','ATF','Africa'),
          ('Gabon','GA','GAB','Africa'),
          ('Gambia','GM','GMB','Africa'),
          ('Georgia','GE','GEO','Asia'),
          ('Germany','DE','DEU','Europe'),
          ('Ghana','GH','GHA','Africa'),
          ('Gibraltar','GI','GIB','Europe'),
          ('Greece','GR','GRC','Europe'),
          ('Greenland','GL','GRL','Americas'),
          ('Grenada','GD','GRD','Americas'),
          ('Guadeloupe','GP','GLP','Americas'),
          ('Guam','GU','GUM','Oceania'),
          ('Guatemala','GT','GTM','Americas'),
          ('Guernsey','GG','GGY','Europe'),
          ('Guinea','GN','GIN','Africa'),
          ('Guinea-Bissau','GW','GNB','Africa'),
          ('Guyana','GY','GUY','Americas'),
          ('Haiti','HT','HTI','Americas'),
          ('Heard Island and McDonald Islands','HM','HMD','Oceania'),
          ('Holy See','VA','VAT','Europe'),
          ('Honduras','HN','HND','Americas'),
          ('Hong Kong','HK','HKG','Asia'),
          ('Hungary','HU','HUN','Europe'),
          ('Iceland','IS','ISL','Europe'),
          ('India','IN','IND','Asia'),
          ('Indonesia','ID','IDN','Asia'),
          ('Iran (Islamic Republic of)','IR','IRN','Asia'),
          ('Iraq','IQ','IRQ','Asia'),
          ('Ireland','IE','IRL','Europe'),
          ('Isle of Man','IM','IMN','Europe'),
          ('Israel','IL','ISR','Asia'),
          ('Italy','IT','ITA','Europe'),
          ('Jamaica','JM','JAM','Americas'),
          ('Japan','JP','JPN','Asia'),
          ('Jersey','JE','JEY','Europe'),
          ('Jordan','JO','JOR','Asia'),
          ('Kazakhstan','KZ','KAZ','Asia'),
          ('Kenya','KE','KEN','Africa'),
          ('Kiribati','KI','KIR','Oceania'),
          ('Korea (Democratic People s Republic of)','KP','PRK','Asia'),
          ('Korea, Republic of','KR','KOR','Asia'),
          ('Kuwait','KW','KWT','Asia'),
          ('Kyrgyzstan','KG','KGZ','Asia'),
          ('Lao People s Democratic Republic','LA','LAO','Asia'),
          ('Latvia','LV','LVA','Europe'),
          ('Lebanon','LB','LBN','Asia'),
          ('Lesotho','LS','LSO','Africa'),
          ('Liberia','LR','LBR','Africa'),
          ('Libya','LY','LBY','Africa'),
          ('Liechtenstein','LI','LIE','Europe'),
          ('Lithuania','LT','LTU','Europe'),
          ('Luxembourg','LU','LUX','Europe'),
          ('Macao','MO','MAC','Asia'),
          ('Madagascar','MG','MDG','Africa'),
          ('Malawi','MW','MWI','Africa'),
          ('Malaysia','MY','MYS','Asia'),
          ('Maldives','MV','MDV','Asia'),
          ('Mali','ML','MLI','Africa'),
          ('Malta','MT','MLT','Europe'),
          ('Marshall Islands','MH','MHL','Oceania'),
          ('Martinique','MQ','MTQ','Americas'),
          ('Mauritania','MR','MRT','Africa'),
          ('Mauritius','MU','MUS','Africa'),
          ('Mayotte','YT','MYT','Africa'),
          ('Mexico','MX','MEX','Americas'),
          ('Micronesia (Federated States of)','FM','FSM','Oceania'),
          ('Moldova, Republic of','MD','MDA','Europe'),
          ('Monaco','MC','MCO','Europe'),
          ('Mongolia','MN','MNG','Asia'),
          ('Montenegro','ME','MNE','Europe'),
          ('Montserrat','MS','MSR','Americas'),
          ('Morocco','MA','MAR','Africa'),
          ('Mozambique','MZ','MOZ','Africa'),
          ('Myanmar','MM','MMR','Asia'),
          ('Namibia','NA','NAM','Africa'),
          ('Nauru','NR','NRU','Oceania'),
          ('Nepal','NP','NPL','Asia'),
          ('Netherlands','NL','NLD','Europe'),
          ('New Caledonia','NC','NCL','Oceania'),
          ('New Zealand','NZ','NZL','Oceania'),
          ('Nicaragua','NI','NIC','Americas'),
          ('Niger','NE','NER','Africa'),
          ('Nigeria','NG','NGA','Africa'),
          ('Niue','NU','NIU','Oceania'),
          ('Norfolk Island','NF','NFK','Oceania'),
          ('North Macedonia','MK','MKD','Europe'),
          ('Northern Mariana Islands','MP','MNP','Oceania'),
          ('Norway','NO','NOR','Europe'),
          ('Oman','OM','OMN','Asia'),
          ('Pakistan','PK','PAK','Asia'),
          ('Palau','PW','PLW','Oceania'),
          ('Palestine, State of','PS','PSE','Asia'),
          ('Panama','PA','PAN','Americas'),
          ('Papua New Guinea','PG','PNG','Oceania'),
          ('Paraguay','PY','PRY','Americas'),
          ('Peru','PE','PER','Americas'),
          ('Philippines','PH','PHL','Asia'),
          ('Pitcairn','PN','PCN','Oceania'),
          ('Poland','PL','POL','Europe'),
          ('Portugal','PT','PRT','Europe'),
          ('Puerto Rico','PR','PRI','Americas'),
          ('Qatar','QA','QAT','Asia'),
          ('Réunion','RE','REU','Africa'),
          ('Romania','RO','ROU','Europe'),
          ('Russian Federation','RU','RUS','Europe'),
          ('Rwanda','RW','RWA','Africa'),
          ('Saint Barthélemy','BL','BLM','Americas'),
          ('Saint Helena, Ascension and Tristan da Cunha','SH','SHN','Africa'),
          ('Saint Kitts and Nevis','KN','KNA','Americas'),
          ('Saint Lucia','LC','LCA','Americas'),
          ('Saint Martin (French part)','MF','MAF','Americas'),
          ('Saint Pierre and Miquelon','PM','SPM','Americas'),
          ('Saint Vincent and the Grenadines','VC','VCT','Americas'),
          ('Samoa','WS','WSM','Oceania'),
          ('San Marino','SM','SMR','Europe'),
          ('Sao Tome and Principe','ST','STP','Africa'),
          ('Saudi Arabia','SA','SAU','Asia'),
          ('Senegal','SN','SEN','Africa'),
          ('Serbia','RS','SRB','Europe'),
          ('Seychelles','SC','SYC','Africa'),
          ('Sierra Leone','SL','SLE','Africa'),
          ('Singapore','SG','SGP','Asia'),
          ('Sint Maarten (Dutch part)','SX','SXM','Americas'),
          ('Slovakia','SK','SVK','Europe'),
          ('Slovenia','SI','SVN','Europe'),
          ('Solomon Islands','SB','SLB','Oceania'),
          ('Somalia','SO','SOM','Africa'),
          ('South Africa','ZA','ZAF','Africa'),
          ('South Georgia and the South Sandwich Islands','GS','SGS','Americas'),
          ('South Sudan','SS','SSD','Africa'),
          ('Spain','ES','ESP','Europe'),
          ('Sri Lanka','LK','LKA','Asia'),
          ('Sudan','SD','SDN','Africa'),
          ('Suriname','SR','SUR','Americas'),
          ('Svalbard and Jan Mayen','SJ','SJM','Europe'),
          ('Sweden','SE','SWE','Europe'),
          ('Switzerland','CH','CHE','Europe'),
          ('Syrian Arab Republic','SY','SYR','Asia'),
          ('Taiwan, Province of China','TW','TWN','Asia'),
          ('Tajikistan','TJ','TJK','Asia'),
          ('Tanzania, United Republic of','TZ','TZA','Africa'),
          ('Thailand','TH','THA','Asia'),
          ('Timor-Leste','TL','TLS','Asia'),
          ('Togo','TG','TGO','Africa'),
          ('Tokelau','TK','TKL','Oceania'),
          ('Tonga','TO','TON','Oceania'),
          ('Trinidad and Tobago','TT','TTO','Americas'),
          ('Tunisia','TN','TUN','Africa'),
          ('Turkey','TR','TUR','Asia'),
          ('Turkmenistan','TM','TKM','Asia'),
          ('Turks and Caicos Islands','TC','TCA','Americas'),
          ('Tuvalu','TV','TUV','Oceania'),
          ('Uganda','UG','UGA','Africa'),
          ('Ukraine','UA','UKR','Europe'),
          ('United Arab Emirates','AE','ARE','Asia'),
          ('United Kingdom of Great Britain and Northern Ireland','GB','GBR','Europe'),
          ('United States of America','US','USA','Americas'),
          ('United States Minor Outlying Islands','UM','UMI','Oceania'),
          ('Uruguay','UY','URY','Americas'),
          ('Uzbekistan','UZ','UZB','Asia'),
          ('Vanuatu','VU','VUT','Oceania'),
          ('Venezuela (Bolivarian Republic of)','VE','VEN','Americas'),
          ('Viet Nam','VN','VNM','Asia'),
          ('Virgin Islands (British)','VG','VGB','Americas'),
          ('Virgin Islands (U.S.)','VI','VIR','Americas'),
          ('Wallis and Futuna','WF','WLF','Oceania'),
          ('Western Sahara','EH','ESH','Africa'),
          ('Yemen','YE','YEM','Asia'),
          ('Zambia','ZM','ZMB','Africa'),
          ('Zimbabwe','ZW','ZWE','Africa');
    END IF;
END $$;''')

with conn.cursor() as cursor:  # creating users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    login VARCHAR(30) UNIQUE NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    countryCode CHAR(2) NOT NULL,
    isPublic BOOLEAN NOT NULL,
    phone VARCHAR(20),
    image VARCHAR(200),
    token VARCHAR(200)
);''')


class Profile:
    def __init__(self, login, email, password, countryCode, isPublic, phone=None, image=None):
        self.login = login
        self.email = email
        self.password = password
        self.countryCode = countryCode
        self.isPublic = isPublic
        self.phone = phone
        self.image = image


def get_country_by_alpha(alpha_code):
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM countries WHERE alpha2 = %s", (alpha_code,))
        country = cursor.fetchone()
    if not country:
        return jsonify('invalid alpha'), 404
    return jsonify(country), 200


# Генерация токена
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Срок действия токена (1 день)
    }
    token = jwt.encode(payload, os.getenv('RANDOM_SECRET'), algorithm='HS256')
    return token.decode('utf-8')


def get_actual_regions():
    with conn.cursor() as cursor:
        cursor.execute('''SELECT DISTINCT region FROM countries;
''')
        return cursor.fetchall


def generate_hash(password):
    # конвертация из строки в набор байтов
    password_bytes = password.encode("utf-8")
    password_salt = bcrypt.gensalt()
    # генерация хэша
    hash_bytes = bcrypt.hashpw(password_bytes, password_salt)
    # конвертация байтов обратно в строку
    hash_str = hash_bytes.decode("utf-8")
    return hash_str


def authenticate(password, hash):
    # конвертируем все из строки в байты
    password_bytes = password.encode("utf-8")
    hash_bytes = hash.encode("utf-8")
    result = bcrypt.checkpw(password_bytes, hash_bytes)
    return result


@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200


# Эндпоинт для получения списка стран
@app.route('/api/countries', methods=['GET'])
def get_countries():
    regions = request.args.get('regions')  # Параметр фильтрации по регионам, если передан
    if regions:
        print(regions)
        regions_list = regions.split(',')
        # Проверка введенных регионов
        actual_regions = get_actual_regions()
        for region in regions_list:
            if region not in actual_regions:
                return jsonify({'message': f'Region "{region}" is invalid'}), 400

        # Генерация строки с плейсхолдерами для каждого региона
        placeholders = ', '.join(['%s' for _ in regions_list])
        # Формируем строку запроса SQL с оператором IN и подставляем значения регионов
        query = f"SELECT name, alpha2, alpha3, region FROM countries WHERE region IN ({placeholders}) ORDER BY alpha2"
        with conn.cursor() as cursor:
            cursor.execute(query, tuple(regions_list))
            countries = cursor.fetchall()
    else:
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, alpha2, alpha3, region FROM countries ORDER BY alpha2")
            countries = cursor.fetchall()
    return jsonify(countries), 200


# Эндпоинт для получения информации о стране по её уникальному двухбуквенному коду
@app.route('/countries/<alpha2>', methods=['GET'])
def get_country(alpha2):
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM countries WHERE alpha2 = %s", (alpha2,))
        country = cursor.fetchone()
        if not country:
            return jsonify({'message': 'Country not found'}), 404
        return jsonify(country), 200


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if data.get('login') is None:
        return jsonify({'error': 'Логин не указан'}), 400
    if data.get('email') is None:
        return jsonify({'error': 'Email не указан'}), 400
    if data.get('password') is None:
        return jsonify({'error': 'Пароль не указан'}), 400
    if data.get('countryCode') is None:
        return jsonify({'error': 'Код страны не указан'}), 400
    if data.get('isPublic') is None:
        return jsonify({'error': 'Флаг isPublic не указан'}), 400

    hashed_password = generate_hash(data['password'])

    if not re.match('^[a-zA-Z0-9]+$', data['login']):
        return jsonify({'error': 'Логин должен содержать только буквы и цифры'}), 400
    if len(data['email']) > 50:
        return jsonify({'error': 'Email слишком длинный (должен быть не более 50 символов)'}), 400
    if len(data['login']) > 30:
        return jsonify({'error': 'Логин слишком длинный (должен быть не более 30 символов)'}), 400
    if len(data['password']) > 50 or len(hashed_password) > 256:
        return jsonify({'error': 'Пароль слишком длинный (должен быть не более 50 символов)'}), 400

    if type(data['isPublic']) is not bool:
        return jsonify({'error': 'Неправильный тип данных isPublic'}), 400

    if len(data['password']) < 6:
        return jsonify({'error': 'Пароль должен содержать не менее 6 символов'}), 400
    if not re.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$", data['password']):
        return jsonify({
            'error': 'Пароль должен содержать латинские символы в верхнем и нижнем регистре и минимум одну цифру'}), 400
    if data.get('phone') is not None:
        if not re.match("^\\+[0-9]+$", data['phone']):
            return jsonify({'error': 'Номер телефона должен начинаться с символа "+" и содержать только цифры'}), 400
    if data.get('image') is not None:
        if len(data['image']) > 200:
            return jsonify({'error': 'Ссылка на изображение слишком длинная (не более 200 символов)'}), 400
    with conn.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM countries WHERE alpha2 = %s", (data['countryCode'],))
        count = cursor.fetchone()[0]
        if count == 0:
            return jsonify({'error': 'Код страны не найден'}), 400

        # Check if login or email already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE login = %s;", (data['login'],))
        count = cursor.fetchone()[0]
        if count != 0:
            return jsonify({'error': 'Login already exists'}), 409

        cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s;", (data['email'],))
        count = cursor.fetchone()[0]
        if count != 0:
            return jsonify({'error': 'Email already exists'}), 409

        cursor.execute('''
            INSERT INTO users (login, email, password_hash, countryCode, isPublic, phone, image)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
            data['login'], data['email'], hashed_password, data['countryCode'], data['isPublic'], data.get('phone'),
            data.get('image'),))
        conn.commit()
        # print("Пользователь успешно зарегистрирован!")
    new_user = Profile(login=data['login'], email=data['email'], password=hashed_password, countryCode=data['countryCode'],
                    isPublic=data['isPublic'])
    return jsonify({
        'login': new_user.login,
        'email': new_user.email,
        'countryCode': new_user.countryCode,
        'isPublic': new_user.isPublic,
        'phone': new_user.phone,
        'image': new_user.image
    }), 201


@app.route('/api/auth/sign-in', methods=['POST'])
def login():
    data = request.get_json()
    with conn.cursor() as cursor:
        cursor.execute('''
            SELECT password_hash FROM users WHERE login = %s;
            ''', (data['login'],))
        real_pass = cursor.fetchone()
        if real_pass is None:
            return jsonify({'message': 'Пользователь с указанным логином не найден'}), 401
        if authenticate(data['password'], real_pass[0]):
            # token = jwt.encode(
            # {'user': data['login'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)},
            # os.getenv('SECRET_KEY'))
            token = jwt.encode(payload={'sub': data['login']}, key='rqvenrieqfoiejq', algorithm='HS256')

            try:
                cursor.execute('''UPDATE users
                    SET token = %s
                    WHERE login = %s;''', (token, data['login'],))
                return jsonify({'token': token}), 200
            except Exception as e:
                return jsonify({'message', 'token saving is failed'}), 404
        else:
            return jsonify({'message': 'Wrong password'}), 401


@app.route('/api/me/profile', methods=['POST'])
def get_profile():
    data = request.get_json()
    with conn.cursor() as cursor:
        if data.get('token') is None:
            return jsonify({'message': 'Token is null'}), 401
        cursor.execute('''
            SELECT EXISTS(SELECT 1 FROM users WHERE token = %s) AS user_exists;
                ''', (data['token'],))
        exists = cursor.fetchone()[0]
        if not exists:
            return jsonify({'message': 'Token does not exists in database'}), 401
        cursor.execute('''
        SELECT id, login, email, country_code, is_public, phone, image
        FROM users
        WHERE token = %s);''', (data['token'],))
        user_data = cursor.fetchall()
    return jsonify(user_data), 200


if __name__ == "__main__":
    app.run()
