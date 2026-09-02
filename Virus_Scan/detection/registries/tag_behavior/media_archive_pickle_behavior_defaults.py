"""Media Archive Pickle tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

MEDIA_ARCHIVE_PICKLE_TAG_TO_BEHAVIOR = freeze_registry_value({'archive_dropper': 'dropper_behavior', 'decoded_payload_rescanned': 'payload_decode', 'dropper_behavior': 'dropper_behavior', 'embedded_archive_payload': 'dropper_behavior', 'embedded_payload_after_eof': 'encoded_payload_candidate', 'encoded_payload': 'encoded_payload', 'encoded_payload_candidate': 'encoded_payload_candidate', 'image_payload_candidate': 'stego_candidate_observation', 'image_stego_lsb_anomaly': 'lsb_statistical_anomaly', 'jpeg_metadata_encoded_reference': 'image_metadata_encoded_reference', 'jpeg_metadata_url_reference': 'image_metadata_url_reference', 'lsb_randomness_anomaly': 'lsb_statistical_anomaly', 'payload_decode_candidate': 'payload_decode', 'pickle_external_file_reference': 'file_access', 'pickle_file_load_context': 'file_access', 'pickle_fragmented_base64_payload': 'encoded_payload_candidate', 'pickle_fragmented_payload': 'encoded_payload_candidate', 'possible_lsb_stego': 'lsb_statistical_anomaly', 'possible_stego_payload': 'stego_statistical_anomaly', 'stego_payload_suspect': 'stego_statistical_anomaly', 'strong_lsb_balance_anomaly': 'lsb_statistical_anomaly', 'url_in_image': 'image_metadata_url_reference'})

__all__ = ("MEDIA_ARCHIVE_PICKLE_TAG_TO_BEHAVIOR",)
