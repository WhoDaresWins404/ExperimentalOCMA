from typing import Type, Optional
from .base import BaseScanner
from core.models import ScannerManifest


class ScannerRegistry:
    _scanners: dict[str, Type[BaseScanner]] = {}
    _manifests: dict[str, ScannerManifest] = {}

    @classmethod
    def register(cls, scanner_cls: Type[BaseScanner], manifest: ScannerManifest = None):
        name = getattr(scanner_cls, "name", None)
        if not name:
            name = scanner_cls.__name__.lower().replace("scanner", "")
        cls._scanners[name] = scanner_cls
        if manifest:
            cls._manifests[name] = manifest
        return scanner_cls

    @classmethod
    def get(cls, name: str) -> Type[BaseScanner]:
        if name not in cls._scanners:
            raise KeyError(f"Scanner '{name}' not registered. Available: {list(cls._scanners.keys())}")
        return cls._scanners[name]

    @classmethod
    def get_manifest(cls, name: str) -> Optional[ScannerManifest]:
        return cls._manifests.get(name)

    @classmethod
    def list_all(cls) -> list[str]:
        return list(cls._scanners.keys())

    @classmethod
    def get_all(cls) -> dict[str, Type[BaseScanner]]:
        return dict(cls._scanners)

    @classmethod
    def get_all_manifests(cls) -> dict[str, ScannerManifest]:
        return dict(cls._manifests)

    @classmethod
    def instantiate_all(
        cls,
        config,
        session_id: str,
        waf_state: dict = None,
        directive_bus=None,
    ) -> dict[str, BaseScanner]:
        instances = {}
        for name, scanner_cls in cls._scanners.items():
            instances[name] = scanner_cls(
                config, session_id, waf_state,
                directive_bus=directive_bus,
            )
        return instances


def register_scanner(cls=None, manifest: ScannerManifest = None):
    if cls is None:
        def wrapper(kls):
            ScannerRegistry.register(kls, manifest)
            return kls
        return wrapper
    ScannerRegistry.register(cls, manifest)
    return cls
