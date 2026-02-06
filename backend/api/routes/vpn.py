"""VPN management routes."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ...dependencies import get_current_user, get_vpn_guardian

router = APIRouter(prefix="/vpn", tags=["vpn"])


class KillSwitchModeRequest(BaseModel):
    mode: str  # full, app_specific, alert_only


@router.get("/status")
async def get_vpn_status(
    current_user: dict = Depends(get_current_user),
):
    """Get current VPN connection status."""
    vpn = get_vpn_guardian()
    return await vpn.get_status()


@router.get("/leak-check")
async def run_leak_check(
    current_user: dict = Depends(get_current_user),
):
    """Run an on-demand VPN leak check."""
    vpn = get_vpn_guardian()
    return await vpn.run_leak_check()


@router.get("/config-audit")
async def run_config_audit(
    current_user: dict = Depends(get_current_user),
):
    """Run a VPN configuration security audit."""
    vpn = get_vpn_guardian()
    return vpn.run_config_audit()


@router.post("/kill-switch/mode")
async def set_kill_switch_mode(
    body: KillSwitchModeRequest,
    current_user: dict = Depends(get_current_user),
):
    """Change the kill switch mode."""
    vpn = get_vpn_guardian()
    return await vpn.set_kill_switch_mode(body.mode)


@router.get("/kill-switch/status")
async def get_kill_switch_status(
    current_user: dict = Depends(get_current_user),
):
    """Get kill switch status."""
    vpn = get_vpn_guardian()
    ks = vpn.kill_switch.state
    return {
        "active": ks.active,
        "mode": ks.mode,
        "activated_at": ks.activated_at.isoformat() if ks.activated_at else None,
    }


@router.get("/routes")
async def get_routing_table(
    current_user: dict = Depends(get_current_user),
):
    """Get current routing table snapshot."""
    vpn = get_vpn_guardian()
    snapshot = vpn.route_monitor.take_snapshot()
    return {
        "timestamp": snapshot.timestamp.isoformat(),
        "total_routes": len(snapshot.routes),
        "default_routes": [
            {"destination": r.destination, "gateway": r.gateway, "interface": r.interface, "metric": r.metric}
            for r in snapshot.default_routes
        ],
        "vpn_routes": [
            {"destination": r.destination, "gateway": r.gateway, "interface": r.interface, "metric": r.metric}
            for r in snapshot.vpn_routes
        ],
        "split_tunnel": vpn.route_monitor.detect_split_tunnel(snapshot),
    }
