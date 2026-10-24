from sqlmodel import Session
from models import ShareLink, User, AccessResult, AccessLog
from fastapi import Request


def log_access(session: Session, link: ShareLink, user: User | None, request: Request, result: AccessResult) -> None:

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    user_id = user.id if user else None
    access_log = AccessLog(
        link_id=link.id, 
        user_id= user_id, 
        result=result, 
        ip_address=ip_address, 
        user_agent= user_agent
        )
    session.add(access_log)
    session.commit()