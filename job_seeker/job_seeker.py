class JobSeeker:
    def __init__(self, name, status=False, skills=None, experience=None, bio=None, availability=None):
        self.name = name
        self.status = status
        self.skills = skills if skills else []
        self.experience = experience
        self.bio = bio
        self.availability = availability
        self.applications = []

    def to_dict(self):
        return {
            'name': self.name,
            'status': self.status,
            'skills': self.skills,
            'experience': self.experience,
            'bio': self.bio,
            'availability': self.availability.isoformat() if self.availability else None,
        }