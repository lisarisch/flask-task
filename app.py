from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, current_user, jwt_required, JWTManager
import hashlib
import logging
import argparse
from hmac import compare_digest

parser = argparse.ArgumentParser()

parser.add_argument('--prod', help="Start as production server.", action='store_true', default=False)
parser.add_argument('--port', help="Port to start the server under.", default=8080, type=int)

args = vars(parser.parse_args())

is_production: bool = args["prod"]
port: int = args["port"]

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s\t[%(asctime)s]\t%(message)s',
    datefmt='%Y-%m-%d %I:%M:%S')

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "Yz9zwn9HxDUNcrgvKlQHRHDQp9F5f2X0"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///flask_task.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

salt = b"$2b$10$X4kv7j5ZcG39WgogSl16au"

logging.info("Starting up API")


def hash_password(password: str):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    first_name = db.Column(db.Text, nullable=False)
    last_name = db.Column(db.Text, nullable=False)
    profession = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)

    def check_password(self, password: str):
        return compare_digest(hash_password(password), self.password)

    def __repr__(self):
        return f"{self.first_name} {self.last_name} ({self.email}): {self.profession}"


# Takes whatever object is passed in as the identity when creating JWTs and converts it to a JSON serializable format
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


# Loads a user from database whenever a protected route is accessed
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@app.route("/", methods=["GET"])
def health_check():
    return "Server is up and running", 200


@app.route("/register", methods=["POST"])
def register():
    email = request.json.get("email")
    first_name = request.json.get("first_name")
    last_name = request.json.get("last_name")
    profession = request.json.get("profession")
    password = hash_password(request.json.get("password"))

    if User.query.filter_by(email=email).one_or_none():
        return jsonify("User already exists"), 400

    db.session.add(User(email=email, first_name=first_name, last_name=last_name, profession=profession,
                        password=password))
    db.session.commit()

    logging.info(f"Registered user with email {email}")

    return jsonify("Registered successfully"), 201


@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email")
    password = request.json.get("password")

    user = User.query.filter_by(email=email).one_or_none()
    if not user or not user.check_password(password):
        return jsonify("Wrong email or password"), 401

    logging.info(f"Logged in user with email {email}")

    access_token = create_access_token(identity=user)
    return jsonify(access_token=access_token), 200


@app.route("/users", methods=["GET"])
def get_all_users():
    return jsonify([str(user) for user in User.query.all()]), 200


@app.route("/user", methods=["GET"])
@jwt_required()
def get_user():
    user = User.query.get(current_user.id)
    
    logging.info(f"Returned information on user with email {user.email}")

    return jsonify(str(user)), 200


@app.route("/user", methods=["PUT"])
@jwt_required()
def update_user():
    current_user.email = request.json.get("email")
    current_user.first_name = request.json.get("first_name")
    current_user.last_name = request.json.get("last_name")
    current_user.profession = request.json.get("profession")
    current_user.password = hash_password(request.json.get("password"))

    db.session.commit()

    logging.info(f"Updated information for user with email {current_user.email}")

    return jsonify(str(current_user)), 200


@app.route("/user", methods=["DELETE"])
@jwt_required()
def delete_user():
    email = current_user.email

    db.session.delete(current_user)
    db.session.commit()

    logging.info(f"Deleted user with email {email}")

    return jsonify("Successfully deleted"), 200


if __name__ == "__main__":
    db.create_all()
    app.run(host="0.0.0.0", debug=not is_production, port=port)
