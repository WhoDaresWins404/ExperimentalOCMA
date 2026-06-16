from typing import Type
from .base import BaseScanner


class ScannerRegistry:
    _scanners: dict[str, Type[BaseScanner]] = {}

    @classmethod
    def register(cls, scanner_cls: Type[BaseScanner]):
        name = getattr(scanner_cls, "name", None)
        if not name:
            name = scanner_cls.__name__.lower().replace("scanner", "")
        cls._scanners[name] = scanner_cls
        return scanner_cls

    @classmethod
    def get(cls, name: str) -> Type[BaseScanner]:
        if name not in cls._scanners:
            raise KeyError(f"Scanner '{name}' not registered. Available: {list(cls._scanners.keys())}")
        return cls._scanners[name]

    @classmethod
    def list_all(cls) -> list[str]:
        return list(cls._scanners.keys())

    @classmethod
    def get_all(cls) -> dict[str, Type[BaseScanner]]:
        return dict(cls._scanners)

    @classmethod
    def instantiate_all(cls, config, session_id: str, waf_state: dict = None) -> dict[str, BaseScanner]:
        instances = {}
        for name, scanner_cls in cls._scanners.items():
            instances[name] = scanner_cls(config, session_id, waf_state)
        return instances


def register_scanner(cls):
    ScannerRegistry.register(cls)
    return cls
