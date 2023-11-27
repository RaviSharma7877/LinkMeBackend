class JobPosting:
    def __init__(self, _id, job_title, user_id, status, company, start_date, end_date, hiring_manager, skill_sets, job_description,is_bookmarked,experience,img):
        self._id = _id
        self.job_title = job_title
        self.user_id = user_id
        self.status = status
        self.company = company
        self.start_date = start_date
        self.end_date = end_date
        self.hiring_manager = hiring_manager
        self.skill_sets = skill_sets
        self.job_description = job_description
        self.is_bookmarked = is_bookmarked
        self.experience  = experience 
        self.img  = img 

    def to_dict(self):
        return {
            '_id': str(self._id),
            'user_id': self.user_id,
            'job_title': self.job_title,
            'status': self.status,
            'company': self.company,
            'start_date': self.start_date,
            'end_date': self.end_date,
            'hiring_manager': self.hiring_manager,
            'skill_sets': self.skill_sets,
            'job_description': self.job_description,
            'is_bookmarked': self.is_bookmarked,
            'experience': self.experience,
            'img': self.img,
        }