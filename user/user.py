from werkzeug.security import check_password_hash,generate_password_hash
import bcrypt


class User:
    def __init__(self, _id, username, password, img=None, name=None, desc=None, status=None, is_active=True):
        self._id = _id
        self.username = username
        self.password = password
        self.img = img
        self.name = name
        self.desc = desc
        self.status = status
        self.is_active = is_active

    def to_dict(self):
        return {
            'user_id': str(self._id) if self.user_id is not None else None,
            'username': self.username,
            'password': self.password,  # Note: Storing passwords in plaintext is not recommended in production.
            'img': self.img,
            'name': self.name,
            'desc': self.desc,
            'status': self.status,
            'is_active': self.is_active,
        }
        
        
    
    def _hash_password(self, password):
        if password is not None:
            if isinstance(password, str):  # Check if password is a string
                password_bytes = password.encode('utf-8')
                hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
                return hashed_password.decode('utf-8')  # Decode bytes to string before storing
            elif isinstance(password, bytes):  # Check if password is already in bytes
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
        # Add your authentication logic here, e.g., return True if the user is authenticated
        return True

    @staticmethod
    def get_user_by_id(user_id, user_collection):
        user_data = user_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(
                _id=str(user_data['_id']),
                username=user_data['username'],
                password=user_data['password'],
                # Add other user attributes as needed
            )
        return None
    
    def __repr__(self):
        return f"User(username='{self.username}', status='{self.status}', is_active={self.is_active})"
