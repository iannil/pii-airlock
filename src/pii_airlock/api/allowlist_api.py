"""
Allowlist management API endpoints.

Provides endpoints for managing allowlists used to exempt
certain entities from PII anonymization.
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from pii_airlock.recognizers.allowlist import (
    AllowlistConfig,
    get_allowlist_registry,
    reload_allowlists,
    clear_caches,
)


# ============================================================================
# Pydantic Models
# ============================================================================


class AllowlistInfo(BaseModel):
    """Information about an allowlist."""

    name: str = Field(..., description="Allowlist name")
    entity_type: str = Field(..., description="PII entity type this applies to")
    enabled: bool = Field(..., description="Whether the allowlist is active")
    entry_count: int = Field(..., description="Number of entries in the allowlist")
    case_sensitive: bool = Field(..., description="Whether matching is case-sensitive")


class AllowlistEntryRequest(BaseModel):
    """Request to add an entry to an allowlist."""

    entry: str = Field(..., description="The entry to add")
    entity_type: Optional[str] = Field(None, description="Entity type (for creating new allowlists)")


class AllowlistBatchRequest(BaseModel):
    """Request to batch add entries to an allowlist."""

    entries: list[str] = Field(..., description="List of entries to add")
    entity_type: Optional[str] = Field(None, description="Entity type (for creating new allowlists)")


class AllowlistCreateRequest(BaseModel):
    """Request to create a new allowlist."""

    name: str = Field(..., description="Allowlist name (unique identifier)")
    entity_type: str = Field(..., description="PII entity type this applies to")
    case_sensitive: bool = Field(False, description="Whether matching is case-sensitive")
    enabled: bool = Field(True, description="Whether the allowlist is initially enabled")


class AllowlistUpdateRequest(BaseModel):
    """Request to update an allowlist."""

    enabled: Optional[bool] = Field(None, description="Whether the allowlist is active")
    case_sensitive: Optional[bool] = Field(None, description="Whether matching is case-sensitive")


class AllowlistEntriesResponse(BaseModel):
    """Response containing allowlist entries."""

    name: str = Field(..., description="Allowlist name")
    entity_type: str = Field(..., description="PII entity type")
    entries: list[str] = Field(..., description="List of entries")
    total: int = Field(..., description="Total number of entries")
    page: int = Field(..., description="Current page (1-indexed)")
    page_size: int = Field(..., description="Number of entries per page")
    has_more: bool = Field(..., description="Whether there are more entries")


# ============================================================================
# Router
# ============================================================================

router = APIRouter(prefix="/api/v1/allowlists", tags=["Allowlist Management"])


# ============================================================================
# Query Endpoints
# ============================================================================


@router.get(
    "",
    response_model=list[AllowlistInfo],
    summary="List all allowlists",
    description="Get a list of all registered allowlists with metadata",
)
async def list_allowlists() -> list[AllowlistInfo]:
    """List all registered allowlists."""
    registry = get_allowlist_registry()
    allowlists = registry.list_allowlists()

    return [
        AllowlistInfo(
            name=alist["name"],
            entity_type=alist["entity_type"],
            enabled=alist["enabled"],
            entry_count=alist["entry_count"],
            case_sensitive=alist["case_sensitive"],
        )
        for alist in allowlists
    ]


@router.get(
    "/{name}",
    response_model=AllowlistInfo,
    summary="Get allowlist details",
    description="Get detailed information about a specific allowlist",
)
async def get_allowlist(name: str) -> AllowlistInfo:
    """Get details about a specific allowlist."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    return AllowlistInfo(
        name=allowlist.name,
        entity_type=allowlist.entity_type,
        enabled=allowlist.enabled,
        entry_count=len(allowlist.entries),
        case_sensitive=allowlist.case_sensitive,
    )


@router.get(
    "/{name}/entries",
    response_model=AllowlistEntriesResponse,
    summary="Get allowlist entries",
    description="Get entries from a specific allowlist with pagination",
)
async def get_allowlist_entries(
    name: str,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(100, ge=1, le=1000, description="Number of entries per page"),
    search: Optional[str] = Query(None, description="Filter entries that contain this string"),
) -> AllowlistEntriesResponse:
    """Get entries from an allowlist with pagination."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    # Get all entries
    all_entries = list(allowlist.entries)

    # Filter by search term if provided
    if search:
        search_lower = search.lower()
        all_entries = [e for e in all_entries if search_lower in e.lower()]

    # Calculate pagination
    total = len(all_entries)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    entries = all_entries[start_idx:end_idx]

    return AllowlistEntriesResponse(
        name=name,
        entity_type=allowlist.entity_type,
        entries=entries,
        total=total,
        page=page,
        page_size=page_size,
        has_more=end_idx < total,
    )


# ============================================================================
# Management Endpoints
# ============================================================================


@router.post(
    "",
    response_model=AllowlistInfo,
    summary="Create a new allowlist",
    description="Create a new empty allowlist",
)
async def create_allowlist(request: AllowlistCreateRequest) -> AllowlistInfo:
    """Create a new allowlist."""
    registry = get_allowlist_registry()

    # Check if allowlist already exists
    if registry.get(request.name):
        raise HTTPException(status_code=409, detail=f"Allowlist '{request.name}' already exists")

    # Create new allowlist
    allowlist = AllowlistConfig(
        name=request.name,
        entity_type=request.entity_type,
        enabled=request.enabled,
        case_sensitive=request.case_sensitive,
    )

    registry.register(allowlist)

    return AllowlistInfo(
        name=allowlist.name,
        entity_type=allowlist.entity_type,
        enabled=allowlist.enabled,
        entry_count=len(allowlist.entries),
        case_sensitive=allowlist.case_sensitive,
    )


@router.post(
    "/{name}/entries",
    summary="Add entry to allowlist",
    description="Add a single entry to an existing allowlist",
)
async def add_allowlist_entry(
    name: str,
    request: AllowlistEntryRequest,
) -> dict[str, str]:
    """Add an entry to an allowlist."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    allowlist.add(request.entry)

    # Clear cache to ensure new entry is recognized
    clear_caches()

    return {
        "message": f"Entry '{request.entry}' added to allowlist '{name}'",
        "entry": request.entry,
        "allowlist": name,
    }


@router.post(
    "/{name}/entries/batch",
    summary="Batch add entries to allowlist",
    description="Add multiple entries to an existing allowlist",
)
async def add_allowlist_entries_batch(
    name: str,
    request: AllowlistBatchRequest,
) -> dict[str, str | int]:
    """Batch add entries to an allowlist."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    added_count = 0
    for entry in request.entries:
        if entry and entry.strip():
            allowlist.add(entry.strip())
            added_count += 1

    # Clear cache
    clear_caches()

    return {
        "message": f"Added {added_count} entries to allowlist '{name}'",
        "allowlist": name,
        "added_count": added_count,
    }


@router.delete(
    "/{name}/entries/{entry}",
    summary="Remove entry from allowlist",
    description="Remove an entry from an allowlist",
)
async def remove_allowlist_entry(
    name: str,
    entry: str,
) -> dict[str, str]:
    """Remove an entry from an allowlist."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    allowlist.remove(entry)

    # Clear cache
    clear_caches()

    return {
        "message": f"Entry removed from allowlist '{name}'",
        "entry": entry,
        "allowlist": name,
    }


@router.put(
    "/{name}",
    response_model=AllowlistInfo,
    summary="Update allowlist",
    description="Update allowlist settings (enabled, case_sensitive)",
)
async def update_allowlist(
    name: str,
    request: AllowlistUpdateRequest,
) -> AllowlistInfo:
    """Update allowlist settings."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    if request.enabled is not None:
        allowlist.enabled = request.enabled

    if request.case_sensitive is not None:
        allowlist.case_sensitive = request.case_sensitive

    # Clear cache if settings changed
    clear_caches()

    return AllowlistInfo(
        name=allowlist.name,
        entity_type=allowlist.entity_type,
        enabled=allowlist.enabled,
        entry_count=len(allowlist.entries),
        case_sensitive=allowlist.case_sensitive,
    )


@router.delete(
    "/{name}",
    summary="Delete allowlist",
    description="Delete an entire allowlist",
)
async def delete_allowlist(name: str) -> dict[str, str]:
    """Delete an allowlist."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    # Remove from registry
    del registry._allowlists[name]

    # Clear cache
    clear_caches()

    return {
        "message": f"Allowlist '{name}' deleted",
        "name": name,
    }


@router.post(
    "/reload",
    summary="Reload all allowlists",
    description="Reload all allowlists from the configured directory",
)
async def reload_all_allowlists() -> dict[str, str | int]:
    """Reload all allowlists from disk."""
    count = reload_allowlists()

    return {
        "message": f"Reloaded {count} allowlists from disk",
        "count": count,
    }


@router.get(
    "/export/{name}",
    summary="Export allowlist",
    description="Export an allowlist as a text file",
)
async def export_allowlist(name: str) -> dict[str, str | list[str]]:
    """Export an allowlist."""
    registry = get_allowlist_registry()
    allowlist = registry.get(name)

    if not allowlist:
        raise HTTPException(status_code=404, detail=f"Allowlist '{name}' not found")

    return {
        "name": name,
        "entity_type": allowlist.entity_type,
        "entries": sorted(allowlist.entries),
    }


def get_allowlist_stats() -> dict:
    """Get statistics about allowlists."""
    registry = get_allowlist_registry()

    total_entries = sum(len(alist.entries) for alist in registry._allowlists.values())
    enabled_count = sum(1 for alist in registry._allowlists.values() if alist.enabled)

    return {
        "total_allowlists": len(registry._allowlists),
        "enabled_allowlists": enabled_count,
        "total_entries": total_entries,
    }


@router.get(
    "/stats/summary",
    summary="Get allowlist statistics",
    description="Get summary statistics about all allowlists",
)
async def get_allowlist_stats_summary() -> dict:
    """Get allowlist statistics."""
    return get_allowlist_stats()
