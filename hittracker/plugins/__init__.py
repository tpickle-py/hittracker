from abc import ABC, abstractmethod
from typing import List, Tuple


class DevicePlugin(ABC):
    @classmethod
    @abstractmethod
    def detect_device(cls, output: str) -> bool:
        pass

    @abstractmethod
    def process_output(self, output: str) -> List[Tuple[str, int]]:
        pass

    @abstractmethod
    def pre_process_output(self, output: str) -> str:
        pass
