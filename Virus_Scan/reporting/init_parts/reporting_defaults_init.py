"""Reporting package bootstrap with no VirusTotal configuration registry."""

from Virus_Scan.runtime.api import publish_init_values


def init_reporting_defaults() -> object:
    return publish_init_values(())


__all__ = ("init_reporting_defaults",)
