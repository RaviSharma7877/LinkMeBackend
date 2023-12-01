class Application:
    def __init__(self, job_seeker_id, job_posting_id, status='Pending', details=None,is_bookmarked=None):
        self.job_seeker_id = job_seeker_id
        self.job_posting_id = job_posting_id
        self.status = status
        self.details = details or {}
        self.is_bookmarked = is_bookmarked

    def to_dict(self):
        return {
            'job_seeker_id': self.job_seeker_id,
            'job_posting_id': self.job_posting_id,
            'status': self.status,
            'details': self.details,
            'is_bookmarked': self.is_bookmarked,
        }
