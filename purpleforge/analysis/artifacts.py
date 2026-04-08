"""Artifact management for binary analysis."""

import hashlib
import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class ArtifactHashes(BaseModel):
    """Cryptographic hashes for an artifact."""
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str] = None


class ArtifactMetadata(BaseModel):
    """Metadata for a managed artifact."""
    artifact_id: str = Field(description="Unique artifact identifier")
    original_filename: str = Field(description="Original file name")
    stored_filename: str = Field(description="Filename in artifact storage")
    file_type: str = Field(description="Detected file type")
    file_size: int = Field(description="File size in bytes")
    hashes: ArtifactHashes = Field(description="File hashes")
    added_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_status: str = Field(default="pending")
    analysis_results: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


def calculate_hashes(file_path: Path) -> ArtifactHashes:
    """
    Calculate multiple hashes for a file.

    Args:
        file_path: Path to file

    Returns:
        ArtifactHashes with MD5, SHA1, SHA256, and optionally ssdeep
    """
    # MD5/SHA1 retained for forensic artifact identification (matches IR
    # tooling and threat-intel feeds), not for security guarantees.
    md5_hash = hashlib.md5(usedforsecurity=False)  # noqa: S324
    sha1_hash = hashlib.sha1(usedforsecurity=False)  # noqa: S324
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    # Try to calculate ssdeep if available
    ssdeep_hash = None
    try:
        import ssdeep
        ssdeep_hash = ssdeep.hash_from_file(str(file_path))
    except ImportError:
        pass
    except Exception:
        pass

    return ArtifactHashes(
        md5=md5_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        sha256=sha256_hash.hexdigest(),
        ssdeep=ssdeep_hash,
    )


def detect_file_type(file_path: Path) -> str:
    """
    Detect file type using magic bytes.

    Args:
        file_path: Path to file

    Returns:
        File type string
    """
    # Read first 16 bytes for magic detection
    with open(file_path, "rb") as f:
        magic = f.read(16)

    # PE executable (Windows)
    if magic[:2] == b"MZ":
        return "PE"

    # ELF executable (Linux)
    if magic[:4] == b"\x7fELF":
        return "ELF"

    # Mach-O (macOS)
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                      b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"

    # PDF
    if magic[:5] == b"%PDF-":
        return "PDF"

    # ZIP/JAR/APK/DOCX
    if magic[:2] == b"PK":
        return "ZIP"

    # Office documents (OLE)
    if magic[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE"

    # Scripts
    if magic[:2] in (b"#!", b"//", b"/*"):
        return "Script"

    # Python bytecode
    if file_path.suffix == ".pyc":
        return "Python-Bytecode"

    # Java class
    if magic[:4] == b"\xca\xfe\xba\xbe":
        return "Java-Class"

    # Check by extension
    ext_map = {
        ".exe": "PE",
        ".dll": "PE",
        ".sys": "PE",
        ".so": "ELF",
        ".dylib": "Mach-O",
        ".py": "Script",
        ".js": "Script",
        ".ps1": "Script",
        ".bat": "Script",
        ".sh": "Script",
        ".vbs": "Script",
    }
    ext = file_path.suffix.lower()
    if ext in ext_map:
        return ext_map[ext]

    return "Unknown"


class ArtifactManager:
    """Manage artifacts for a run."""

    def __init__(self, run_dir: Path):
        """
        Initialize artifact manager.

        Args:
            run_dir: Path to run directory
        """
        self.run_dir = run_dir
        self.artifacts_dir = run_dir / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.artifacts_dir / "manifest.json"
        self._artifacts: Dict[str, ArtifactMetadata] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        """Load artifact manifest from disk."""
        if self.manifest_path.exists():
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for artifact_id, artifact_data in data.items():
                self._artifacts[artifact_id] = ArtifactMetadata(**artifact_data)

    def _save_manifest(self) -> None:
        """Save artifact manifest to disk."""
        data = {
            aid: artifact.model_dump(mode="json")
            for aid, artifact in self._artifacts.items()
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def add_artifact(
        self,
        file_path: Path,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None,
    ) -> ArtifactMetadata:
        """
        Add an artifact to the collection.

        Args:
            file_path: Path to artifact file
            tags: Optional tags for categorization
            notes: Optional notes

        Returns:
            ArtifactMetadata for the added artifact
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Artifact not found: {file_path}")

        artifact_id = str(uuid.uuid4())
        file_type = detect_file_type(file_path)
        hashes = calculate_hashes(file_path)
        file_size = file_path.stat().st_size

        # Store with hash-based filename to deduplicate
        stored_filename = f"{hashes.sha256[:16]}_{file_path.name}"
        stored_path = self.artifacts_dir / stored_filename

        # Copy file to artifacts directory
        shutil.copy2(file_path, stored_path)

        metadata = ArtifactMetadata(
            artifact_id=artifact_id,
            original_filename=file_path.name,
            stored_filename=stored_filename,
            file_type=file_type,
            file_size=file_size,
            hashes=hashes,
            tags=tags or [],
            notes=notes,
        )

        self._artifacts[artifact_id] = metadata
        self._save_manifest()

        logger.info(f"Added artifact: {file_path.name} ({file_type}, {file_size} bytes)")
        return metadata

    def get_artifact(self, artifact_id: str) -> Optional[ArtifactMetadata]:
        """Get artifact metadata by ID."""
        return self._artifacts.get(artifact_id)

    def get_artifact_path(self, artifact_id: str) -> Optional[Path]:
        """Get path to stored artifact file."""
        artifact = self.get_artifact(artifact_id)
        if artifact:
            return self.artifacts_dir / artifact.stored_filename
        return None

    def list_artifacts(self) -> List[ArtifactMetadata]:
        """List all artifacts."""
        return list(self._artifacts.values())

    def update_analysis_results(
        self,
        artifact_id: str,
        results: Dict[str, Any],
        status: str = "analyzed",
    ) -> None:
        """
        Update artifact with analysis results.

        Args:
            artifact_id: Artifact identifier
            results: Analysis results dictionary
            status: New analysis status
        """
        if artifact_id not in self._artifacts:
            raise ValueError(f"Artifact not found: {artifact_id}")

        self._artifacts[artifact_id].analysis_results = results
        self._artifacts[artifact_id].analysis_status = status
        self._save_manifest()

    def remove_artifact(self, artifact_id: str) -> bool:
        """
        Remove an artifact.

        Args:
            artifact_id: Artifact identifier

        Returns:
            True if removed, False if not found
        """
        if artifact_id not in self._artifacts:
            return False

        artifact = self._artifacts[artifact_id]
        stored_path = self.artifacts_dir / artifact.stored_filename

        if stored_path.exists():
            stored_path.unlink()

        del self._artifacts[artifact_id]
        self._save_manifest()
        return True
