"""证书管理模块.

负责第三方机构证书的上传、删除、注册表维护和按 issuer DID 定位证书。
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from .config import config
from .logger import get_logger

logger = get_logger(__name__)


class CertificateManager:
    """管理 certs 目录中的第三方证书."""

    BUILTIN_CERT_NAMES = {
        "CMCC_cert.crt",
        "idm_private_key.pem",
        "idm_public_key.pem",
    }

    ISSUER_CERT_RULES = {
        "did:huaweiissuer": {
            "preferred_names": ["Huawei_cert.crt"],
            "keywords": ["huawei"],
        },
        "did:robotfactoryissuer": {
            "preferred_names": ["Robot_Factory_cert.crt", "Robot_Factory_Cert.crt"],
            "keywords": ["robotfactory", "robot_factory"],
        },
        "did:udid:idm": {
            "preferred_names": ["CMCC_cert.crt"],
            "keywords": ["cmcc"],
        },
    }

    @classmethod
    def _normalize_name(cls, name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.lower())

    @classmethod
    def _sanitize_filename(cls, filename: str) -> str:
        safe_name = Path(filename).name.strip()
        if not safe_name:
            raise ValueError("certName is required")
        logger.info(f"Normalized certificate filename: raw={filename}, normalized={safe_name}")
        return safe_name

    @classmethod
    def _load_registry(cls) -> Dict[str, Dict[str, str]]:
        registry_path = config.CERT_REGISTRY_PATH
        if not registry_path.exists():
            logger.info(f"Certificate registry does not exist yet: {registry_path}")
            return {}

        try:
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            logger.info(
                f"Loaded certificate registry: path={registry_path}, entries={len(registry)}"
            )
            return registry
        except Exception as exc:
            logger.warning(f"Failed to read cert registry {registry_path}: {exc}")
            return {}

    @classmethod
    def _save_registry(cls, registry: Dict[str, Dict[str, str]]) -> None:
        config.ensure_directories()
        config.CERT_REGISTRY_PATH.write_text(
            json.dumps(registry, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(
            f"Saved certificate registry: path={config.CERT_REGISTRY_PATH}, entries={len(registry)}"
        )

    @classmethod
    def _is_builtin_cert(cls, cert_name: str) -> bool:
        return cls._sanitize_filename(cert_name) in cls.BUILTIN_CERT_NAMES

    @classmethod
    def upload_certificate(cls, cert_id: str, cert_name: str, file_bytes: bytes) -> Path:
        """保存第三方机构证书到 certs 目录."""
        if not cert_id:
            raise ValueError("certID is required")
        if not file_bytes:
            raise ValueError("file is empty")

        safe_name = cls._sanitize_filename(cert_name)
        if cls._is_builtin_cert(safe_name):
            raise ValueError(f"Built-in certificate cannot be overwritten: {safe_name}")

        config.ensure_directories()
        cert_path = config.CERTS_DIR / safe_name
        registry = cls._load_registry()
        existing = registry.get(cert_id)
        logger.info(
            "Uploading certificate: "
            f"certID={cert_id}, certName={safe_name}, bytes={len(file_bytes)}, target={cert_path}"
        )

        if existing:
            previous_name = existing.get("cert_name")
            logger.info(
                f"Existing certificate registry entry found for certID={cert_id}: {existing}"
            )
            if previous_name and previous_name != safe_name and not cls._is_builtin_cert(previous_name):
                previous_path = config.CERTS_DIR / previous_name
                if previous_path.exists():
                    logger.info(
                        f"Removing previously registered certificate file: {previous_path}"
                    )
                    previous_path.unlink()

        cert_path.write_bytes(file_bytes)
        registry[cert_id] = {
            "cert_name": safe_name,
            "cert_path": str(cert_path),
            "uploaded_at": datetime.utcnow().isoformat() + "Z",
        }
        cls._save_registry(registry)
        logger.info(f"Uploaded certificate {safe_name} for certID={cert_id}")
        return cert_path

    @classmethod
    def delete_certificate(cls, cert_id: str, cert_name: str) -> Optional[Path]:
        """删除第三方机构证书."""
        if not cert_id:
            raise ValueError("certID is required")

        safe_name = cls._sanitize_filename(cert_name)
        if cls._is_builtin_cert(safe_name):
            raise ValueError(f"Built-in certificate cannot be deleted: {safe_name}")

        registry = cls._load_registry()
        entry = registry.get(cert_id)
        logger.info(f"Deleting certificate: certID={cert_id}, certName={safe_name}")
        if not entry:
            raise ValueError(f"Certificate not found for certID: {cert_id}")

        registered_name = entry.get("cert_name")
        logger.info(
            f"Matched certificate registry entry for deletion: certID={cert_id}, entry={entry}"
        )
        if registered_name != safe_name:
            raise ValueError(
                f"Certificate name mismatch for certID {cert_id}: expected {registered_name}, got {safe_name}"
            )

        cert_path = config.CERTS_DIR / safe_name
        if cert_path.exists():
            logger.info(f"Removing certificate file from disk: {cert_path}")
            cert_path.unlink()
        else:
            logger.warning(f"Certificate file already absent during delete: {cert_path}")

        registry.pop(cert_id, None)
        cls._save_registry(registry)
        logger.info(f"Deleted certificate {safe_name} for certID={cert_id}")
        return cert_path

    @classmethod
    def get_certificate_path_for_issuer(cls, issuer_did: str) -> Optional[Path]:
        """根据 issuer DID 找到对应证书文件."""
        if not config.CERTS_DIR.exists():
            logger.warning(f"Certificate directory does not exist: {config.CERTS_DIR}")
            return None

        logger.info(f"Resolving certificate path for issuer DID: {issuer_did}")
        for issuer_prefix, rule in cls.ISSUER_CERT_RULES.items():
            if not issuer_did.startswith(issuer_prefix):
                continue

            logger.info(
                f"Issuer DID matched rule: prefix={issuer_prefix}, preferred={rule['preferred_names']}"
            )

            # 先按 issuer DID 的固定映射查找目标证书文件。
            for preferred_name in rule["preferred_names"]:
                candidate = config.CERTS_DIR / preferred_name
                logger.info(f"Trying preferred certificate candidate: {candidate}")
                if candidate.exists():
                    logger.info(
                        f"Resolved certificate by preferred name for issuer {issuer_did}: {candidate}"
                    )
                    return candidate

            # 仅保留一个窄范围兜底，兼容同机构证书名存在轻微大小写或分隔符差异。
            keywords = [cls._normalize_name(keyword) for keyword in rule["keywords"]]
            logger.info(
                f"Preferred certificate file not found for issuer {issuer_did}, fallback keywords={keywords}"
            )
            for candidate in sorted(config.CERTS_DIR.iterdir()):
                if not candidate.is_file():
                    continue
                normalized = cls._normalize_name(candidate.name)
                if any(keyword in normalized for keyword in keywords):
                    logger.info(
                        f"Resolved certificate by fallback keyword for issuer {issuer_did}: {candidate}"
                    )
                    return candidate

            logger.warning(f"No certificate file found for issuer rule: {issuer_did}")
        return None
