"""
CHANAKYA OPSEC Framework - Kernel Module

Kernel-adjacent signal analysis for low-level attribution vectors.
"""

from .syscall_analyzer import KernelSyscallAnalyzer

__all__ = ['KernelSyscallAnalyzer']
