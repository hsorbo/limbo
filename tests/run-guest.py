#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path

SKIP = 77

MAGICS = {
    "Mach-O 64-bit": r"\xcf\xfa\xed\xfe",
    "Fat Mach-O": r"\xca\xfe\xba\xbe",
}


def main():
    limbo, source, outdir = sys.argv[1:4]
    sysroot = os.environ.get("LIMBO_SYSROOT")
    if sysroot is None:
        skip("LIMBO_SYSROOT is not set")
    xcrun = Path(sysroot) / "usr" / "bin" / "xcrun"
    if not xcrun.exists():
        skip(f"{xcrun} does not exist")

    if os.environ.get("LIMBO_TEST_NAMESPACE") is None:
        enter_namespace()

    register_binfmt(Path(limbo).resolve(), Path(outdir) / "binfmt")
    binary = compile_program(xcrun, Path(source), Path(outdir))
    result = subprocess.run([binary], cwd=outdir, timeout=240)
    sys.exit(result.returncode)


def skip(reason):
    print(f"skipping: {reason}")
    sys.exit(SKIP)


def enter_namespace():
    env = dict(os.environ, LIMBO_TEST_NAMESPACE="1")
    try:
        result = subprocess.run(["unshare", "--user", "--map-root-user",
                                 "--mount", "--propagation", "private",
                                 sys.executable] + sys.argv, env=env)
    except FileNotFoundError:
        skip("unshare is not available")
    sys.exit(result.returncode)


def register_binfmt(limbo, mountpoint):
    mountpoint.mkdir(exist_ok=True)
    result = subprocess.run(["mount", "-t", "binfmt_misc", "binfmt_misc",
                             mountpoint], capture_output=True, text=True)
    if result.returncode != 0:
        skip("binfmt_misc cannot be mounted in a user namespace: "
             + result.stderr.strip())

    register = mountpoint / "register"
    for name, magic in MAGICS.items():
        register.write_text(f":{name}:M::{magic}::{limbo}:FP\n")


def compile_program(xcrun, source, outdir):
    binary = outdir / source.stem
    inputs = [source, source.parent.parent / "check.h"]
    if binary.exists() and all(binary.stat().st_mtime >= path.stat().st_mtime
                               for path in inputs):
        return binary

    compiler = "clang++" if source.suffix == ".cpp" else "clang"
    flags = ["-std=c++23"] if source.suffix == ".cpp" else []
    command = [xcrun, compiler, *flags, "-Wall", "-Werror",
               "-I", source.parent.parent, "-o", binary, source,
               "-framework", "CoreFoundation"]
    result = subprocess.run(command, timeout=240)
    if result.returncode != 0:
        sys.exit(result.returncode)
    return binary


if __name__ == "__main__":
    main()
