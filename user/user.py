from bson import ObjectId
from werkzeug.security import check_password_hash, generate_password_hash
import bcrypt


class User:
    def __init__(self, _id, username, password, is_admin=False, img=None, fullName=None, description=None, email=None, status=None, is_active=True, skills=None):
        self._id = _id
        self.username = username
        self.password = self._hash_password(password)
        self.is_admin = is_admin
        self.img = img
        self.fullName = fullName
        self.description = description
        self.email = email
        self.status = status
        self.is_active = is_active
        self.skills = skills if skills is not None else []

    def to_dict(self):
        return {
            'user_id': str(self._id) if self._id is not None else None,
            'username': self.username,
            'password': self.password,
            'is_admin': self.is_admin,
            'img': self.img,
            'fullName': self.fullName,
            'description': self.description,
            'email': self.email,
            'status': self.status,
            'is_active': self.is_active,
            'skills': self.skills,
        }

    def _hash_password(self, password):
        if password is not None:
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
                hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
                return hashed_password.decode('utf-8')
            elif isinstance(password, bytes):
                raise ValueError("Password must be a string")
            else:
                raise ValueError("Password must be a string or bytes")
        else:
            return None

    def check_password(self, password):
        return check_password_hash(self.password, password) if self.password is not None else False

    def get_id(self):
        return str(self._id) if self._id is not None else None

    @property
    def is_authenticated(self):
        return True

    @staticmethod
    def get_user_by_id(user_id, user_collection):
        user_data = user_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(
                _id=str(user_data['_id']),
                username=user_data['username'],
                password=user_data['password'],
                is_admin=user_data.get('is_admin', False),
            )
        return None

    def __repr__(self):
        return f"User(username='{self.username}', email='{self.email}', is_active={self.is_active})"
