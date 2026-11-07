"""
AegisShield - PE Binary Analyzer & Heuristic Scanner
Pure Python PE Header Parsing, Shannon Entropy Calculation,
Cryptographic Hashing, and Suspicious API String Inspection.
"""

import os
import math
import struct
import hashlib
from typing import Dict, List, Optional, Any
from .signatures_db import SUSPICIOUS_PE_APIS

# Cache results by file path and modified timestamp
_ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy of byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    # Byte frequency count
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)


def get_file_hashes(file_path: str) -> Dict[str, str]:
    """Calculate SHA256 and MD5 hashes of a file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest()
        }
    except Exception:
        return {"sha256": "Unavailable (Locked/Inaccessible)", "md5": "Unavailable"}


def parse_pe_headers(file_path: str) -> Dict[str, Any]:
    """
    Pure Python PE header inspection.
    Extracts architecture, section count, entropy, and detects packed code.
    """
    info = {
        "is_pe": False,
        "machine": "Unknown",
        "sections": [],
        "file_entropy": 0.0,
        "is_packed": False,
        "matched_apis": [],
        "api_score": 0
    }

    if not os.path.isfile(file_path):
        return info

    try:
        file_size = os.path.getsize(file_path)
        # Limit scanning large files > 50MB for responsiveness
        if file_size > 50 * 1024 * 1024:
            return info

        with open(file_path, "rb") as f:
            header_sample = f.read(min(file_size, 4096))
            if len(header_sample) < 64:
                return info

            # Check DOS MZ signature
            if header_sample[:2] != b"MZ":
                return info

            # Offset to PE signature is at offset 0x3C (DWORD)
            e_lfanew = struct.unpack_from("<I", header_sample, 0x3C)[0]
            if e_lfanew + 24 > file_size:
                return info

            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return info

            info["is_pe"] = True

            # COFF File Header (20 bytes)
            coff_header = f.read(20)
            if len(coff_header) == 20:
                machine, num_sections, timedatestamp, _, _, size_of_opt_header, characteristics = struct.unpack(
                    "<HHIIIHH", coff_header
                )
                if machine == 0x014C:
                    info["machine"] = "x86 (32-bit)"
                elif machine == 0x8664:
                    info["machine"] = "x64 (64-bit)"
                elif machine == 0xAA64:
                    info["machine"] = "ARM64"
                else:
                    info["machine"] = f"0x{machine:04x}"

                # Read sections if available
                opt_header_data = f.read(size_of_opt_header)
                section_headers_data = f.read(num_sections * 40)
                
                sections_info = []
                for i in range(min(num_sections, 16)):
                    offset = i * 40
                    if offset + 40 <= len(section_headers_data):
                        sec_bytes = section_headers_data[offset:offset + 40]
                        name = sec_bytes[:8].decode("utf-8", errors="ignore").strip("\x00")
                        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack("<IIII", sec_bytes[8:24])
                        sections_info.append({
                            "name": name,
                            "raw_size": raw_size,
                            "virt_size": virt_size
                        })
                info["sections"] = sections_info

            # Read full or sampled content for entropy and suspicious strings
            f.seek(0)
            sample_for_entropy = f.read(min(file_size, 1024 * 1024))  # Sample up to 1MB
            entropy = calculate_entropy(sample_for_entropy)
            info["file_entropy"] = entropy

            # Packed executable indicator: High entropy > 7.15
            if entropy > 7.15:
                info["is_packed"] = True

            # Scan for suspicious API strings in binary
            f.seek(0)
            content = f.read(min(file_size, 2 * 1024 * 1024))  # Read up to 2MB for string matching
            matched_apis = []
            api_score = 0

            for api_name, meta in SUSPICIOUS_PE_APIS.items():
                api_bytes = api_name.encode("ascii")
                if api_bytes in content:
                    matched_apis.append({
                        "api": api_name,
                        "role": meta["role"],
                        "score": meta["score"]
                    })
                    api_score += meta["score"]

            info["matched_apis"] = matched_apis
            info["api_score"] = min(api_score, 60)

    except (PermissionError, OSError):
        pass
    except Exception:
        pass

    return info


def analyze_binary(file_path: str) -> Dict[str, Any]:
    """
    Cached analysis wrapper for executable binaries.
    Returns hashes, entropy, PE data, and matched suspicious APIs.
    """
    if not file_path or not os.path.exists(file_path):
        return {
            "exists": False,
            "file_path": file_path,
            "hashes": {"sha256": "N/A", "md5": "N/A"},
            "is_pe": False,
            "file_entropy": 0.0,
            "is_packed": False,
            "matched_apis": [],
            "api_score": 0
        }

    try:
        mtime = os.path.getmtime(file_path)
        cache_key = f"{file_path}_{mtime}"
        if cache_key in _ANALYSIS_CACHE:
            return _ANALYSIS_CACHE[cache_key]

        hashes = get_file_hashes(file_path)
        pe_info = parse_pe_headers(file_path)

        result = {
            "exists": True,
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "hashes": hashes,
            **pe_info
        }

        # Cache top 300 scanned binaries
        if len(_ANALYSIS_CACHE) > 300:
            _ANALYSIS_CACHE.clear()
        _ANALYSIS_CACHE[cache_key] = result
        return result

    except Exception:
        return {
            "exists": False,
            "file_path": file_path,
            "hashes": {"sha256": "Error", "md5": "Error"},
            "is_pe": False,
            "file_entropy": 0.0,
            "is_packed": False,
            "matched_apis": [],
            "api_score": 0
        }

