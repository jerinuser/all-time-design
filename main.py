from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import os
import secrets

from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

MONGO_URI = os.getenv("MONGO_URI")

db_name = os.getenv("DB_NAME")

client = MongoClient(MONGO_URI)

db = client[db_name]


app.config["JWT_SECRET_KEY"] = secrets.token_hex(32)  
jwt = JWTManager(app)

@app.route("/register", methods=["POST"])
def register():
    data = request.json

    
    required_fields = ["first_name", "last_name", "email", "password"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Missing {field}"}), 400

    
    if db.users.find_one({"email": data["email"]}):
        return jsonify({"error": "User already exists"}), 400

   
    password_bytes = data["password"].encode("utf-8")
    hashed_pw = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    
    user = {
        "first_name": data["first_name"],
        "last_name": data["last_name"],
        "email": data["email"],
        "password": hashed_pw.decode("utf-8"),  
    }


    db.users.insert_one(user)

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = db.users.find_one({"email": data["email"]})

    if user and bcrypt.checkpw(data["password"].encode("utf-8"), user["password"].encode("utf-8")):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/template", methods=["POST"])
@jwt_required()
def create_template():
    user_id = get_jwt_identity()
    data = request.json

    template = {
        "user_id": user_id,
        "template_name": data.get("template_name"),
        "subject": data.get("subject"),
        "body": data.get("body"),
    }
    result = db.templates.insert_one(template)
    return jsonify({"message": "Template created", "id": str(result.inserted_id)}), 201



@app.route("/template", methods=["GET"])
@jwt_required()
def get_templates():
    user_id = get_jwt_identity()
    templates = list(db.templates.find({"user_id": user_id}, {"_id": 1, "template_name": 1, "subject": 1, "body": 1}))

    for template in templates:
        template["_id"] = str(template["_id"])

    return jsonify({"templates": templates}), 200


@app.route("/template/<template_id>", methods=["GET"])
@jwt_required()
def get_single_template(template_id):
    user_id = get_jwt_identity()
    template = db.templates.find_one({"_id": ObjectId(template_id), "user_id": user_id})

    if not template:
        return jsonify({"error": "Template not found"}), 404

    template["_id"] = str(template["_id"])
    return jsonify(template), 200

@app.route("/template/<template_id>", methods=["PUT"])
@jwt_required()
def update_template(template_id):
    user_id = get_jwt_identity()
    data = request.json

    updated = db.templates.update_one(
        {"_id": ObjectId(template_id), "user_id": user_id},
        {"$set": {"template_name": data.get("template_name"), "subject": data.get("subject"), "body": data.get("body")}},
    )

    if updated.matched_count == 0:
        return jsonify({"error": "Template not found"}), 404

    return jsonify({"message": "Template updated"}), 200


@app.route("/template/<template_id>", methods=["DELETE"])
@jwt_required()
def delete_template(template_id):
    user_id = get_jwt_identity()
    deleted = db.templates.delete_one({"_id": ObjectId(template_id), "user_id": user_id})

    if deleted.deleted_count == 0:
        return jsonify({"error": "Template not found"}), 404

    return jsonify({"message": "Template deleted"}), 200

if __name__ == "__main__":
    app.run(debug=True)
