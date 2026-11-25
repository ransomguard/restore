"""Installer operation for the directory that owns the protected state tree."""
import os
from pathlib import Path
import stat
import subprocess


def protect_state_parent(directory):
    """Prevent an ordinary Administrators delete-child open on this directory only."""
    directory=Path(directory).absolute()
    for entry in (directory, *directory.parents):
        info=entry.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Unexpected service state ancestor")
    # No inheritance flags and no recursion. Existing rights on other package
    # children, including their individual DELETE grants, are retained.
    icacls=Path(os.environ["SystemRoot"])/"System32/icacls.exe"
    subprocess.run([str(icacls),str(directory),"/deny","*S-1-5-32-544:(DC)"],
                   check=True,capture_output=True,timeout=30)


if __name__=="__main__":
    import sys
    # An installation command may address only its own Program Files bundle.
    bundle=Path(sys.executable).absolute().parent.parent
    expected=Path(os.environ["ProgramFiles"])/"RansomGuard"
    if len(sys.argv)!=1 or bundle.parent!=expected or Path(__file__).absolute().parents[2]!=bundle:
        raise RuntimeError("Use the installed Ransom0 bundle to provision its own state parent")
    protect_state_parent(bundle)
