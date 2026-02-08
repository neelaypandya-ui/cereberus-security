"""Disk cleanup routes — analyze disk usage, execute cleanup, find large files."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_EXECUTE_REMEDIATION
from ...dependencies import get_disk_analyzer

router = APIRouter(prefix="/disk-cleanup", tags=["disk-cleanup"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class CleanupRequest(BaseModel):
    categories: list[str]


class DeleteFileRequest(BaseModel):
    path: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/analysis")
async def run_disk_analysis(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Run disk analysis and return categories with sizes."""
    analyzer = get_disk_analyzer()
    try:
        result = await analyzer.analyze()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Disk analysis failed: {e}")

    return {
        "disk_usage": result.get("disk_usage", {}),
        "categories": result.get("categories", []),
        "total_cleanable_bytes": result.get("total_cleanable_bytes", 0),
    }


@router.post("/clean")
async def execute_cleanup(
    body: CleanupRequest,
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Execute cleanup for selected categories."""
    analyzer = get_disk_analyzer()

    # Validate that all requested categories are known
    known_categories = analyzer.known_categories
    unknown = [c for c in body.categories if c not in known_categories]
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown categories: {unknown}. Valid categories: {sorted(known_categories)}",
        )

    try:
        result = await analyzer.clean(body.categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {e}")

    return {
        "results": result.get("results", {}),
        "total_freed": result.get("total_freed", 0),
    }


@router.get("/large-files")
async def find_large_files(
    min_size_mb: int = Query(100, ge=1, description="Minimum file size in MB"),
    limit: int = Query(20, ge=1, le=500, description="Maximum number of files to return"),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Find large files on disk."""
    analyzer = get_disk_analyzer()
    try:
        files = await analyzer.find_large_files(min_size_mb, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Large file scan failed: {e}")

    return {"files": files}


@router.delete("/file")
async def delete_file(
    body: DeleteFileRequest,
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Delete a single file. Restricted to user home directory."""
    analyzer = get_disk_analyzer()
    try:
        result = await analyzer.delete_file(body.path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File deletion failed: {e}")

    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])

    return result
