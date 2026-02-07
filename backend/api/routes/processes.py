"""Process Analyzer API routes."""

from fastapi import APIRouter, Depends, HTTPException

from ...dependencies import get_current_user, get_process_analyzer

router = APIRouter(prefix="/processes", tags=["processes"])


@router.get("/")
async def get_processes(current_user: dict = Depends(get_current_user)):
    """Get all running processes."""
    analyzer = get_process_analyzer()
    return analyzer.get_processes()


@router.get("/suspicious")
async def get_suspicious_processes(current_user: dict = Depends(get_current_user)):
    """Get suspicious processes."""
    analyzer = get_process_analyzer()
    return analyzer.get_suspicious()


@router.get("/{pid}/tree")
async def get_process_tree(pid: int, current_user: dict = Depends(get_current_user)):
    """Get process tree for a specific PID."""
    analyzer = get_process_analyzer()
    tree = analyzer.get_process_tree(pid)
    if tree is None:
        raise HTTPException(status_code=404, detail="Process not found")
    return tree
