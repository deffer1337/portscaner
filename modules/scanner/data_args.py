from dataclasses import dataclass
from typing import Dict, Set


@dataclass
class _DataArgs:
    """ class for class PortScanArgumentParser """
    ip: str
    ports: Dict[str, Set[int]]
    timeout: float
    verbose: bool
    guess: bool
