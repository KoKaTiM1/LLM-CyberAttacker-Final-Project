import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.target_spec import build_file_target_spec


def test_build_file_target_spec_detects_c_source_in_txt_file():
    file_content = """#include <stdio.h>
#include <string.h>

int main() {
    char buf[64];
    scanf("%63s", buf);
    printf("%s\\n", buf);
    return 0;
}
"""

    spec = build_file_target_spec(
        file_path="src/data/lcp-data set/files/File2.txt",
        file_content=file_content,
    )

    assert spec.metadata["source_language"] == "c"
    assert spec.container_target_path == "/tmp/target.c"
    assert spec.compile_command is not None
    assert spec.run_command == "/tmp/target"


def test_build_file_target_spec_keeps_plain_text_as_text():
    spec = build_file_target_spec(
        file_path="notes.txt",
        file_content="this is plain text with no source code markers",
    )

    assert spec.metadata["source_language"] == "text"
    assert spec.container_target_path == "/tmp/target.txt"
    assert spec.compile_command is None
    assert spec.run_command is None
