"""Launcher that replaces the Python agent-shim with the Java one.

The pinned upstream shim check spawns `python <UMA4A_REPO>/clients/agent-shim/shim.py`.
This file sits at that path in the Java runtime tree and replaces its own process with
the Java shim, so the process under test is the JVM. Arguments and environment pass
through unchanged.
"""

import os
import sys

SHIM_JAR = os.environ.get("UMA4A_JAVA_SHIM_JAR", "/app/shim.jar")


def main() -> None:
    """Exec the Java shim in place of this interpreter."""
    if not os.path.isfile(SHIM_JAR):
        sys.exit(f"Java shim jar not found at {SHIM_JAR}; set UMA4A_JAVA_SHIM_JAR")
    print(f"uma4a launcher: exec java -jar {SHIM_JAR}", file=sys.stderr, flush=True)
    os.execvp("java", ["java", "-jar", SHIM_JAR, *sys.argv[1:]])


if __name__ == "__main__":
    main()
