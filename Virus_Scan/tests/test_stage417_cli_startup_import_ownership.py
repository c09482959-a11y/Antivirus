import subprocess
import sys
import textwrap


def test_cli_args_import_does_not_eagerly_import_scanners_or_detection_tags():
    code = textwrap.dedent(
        """
        import sys
        import Virus_Scan.cli.args
        forbidden = [
            'Virus_Scan.scanners.binary',
            'Virus_Scan.detection.tags',
            'Virus_Scan.detection.scoring.adaptive.model_score',
            'Virus_Scan.reporting.output',
        ]
        loaded_modules = vars(sys)['modules']
        loaded = [name for name in forbidden if name in loaded_modules]
        if loaded:
            raise SystemExit('eager startup imports: ' + ','.join(loaded))
        """
    )
    proc = subprocess.run([sys.executable, '-c', code], text=True, capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr + proc.stdout
