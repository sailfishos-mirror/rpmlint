import pytest
from rpmlint.checks.SourceCheck import SourceCheck
from rpmlint.filter import Filter

from Testing import CONFIG, get_tested_mock_package, get_tested_package


@pytest.fixture(scope='function', autouse=True)
def sourcescheck():
    CONFIG.info = True
    output = Filter(CONFIG)
    test = SourceCheck(CONFIG, output)
    return output, test


@pytest.mark.parametrize('package', ['source/wrongsrc'])
def test_extension_and_permissions(tmp_path, package, sourcescheck):
    output, test = sourcescheck
    test.check(get_tested_package(package, tmp_path))
    out = output.print_results(output.results)

    assert len(output.results) == 1

    assert 'inconsistent-file-extension' in out
    assert 'name extension indicates a different compression format' in out

    assert 'strange-permission' not in out
    assert 'a file should have' not in out


@pytest.mark.parametrize('package', ['source/not-compressed-multi-spec'])
def test_compression_and_multispec(tmp_path, package, sourcescheck):
    output, test = sourcescheck
    test.check(get_tested_package(package, tmp_path))
    out = output.print_results(output.results)

    assert 'source-not-compressed' in out
    assert 'source archive or file in your package is not compressed' in out

    assert 'multiple-specfiles' in out
    assert 'package contains multiple spec files' in out


# ── Tests for _check_file_ext (compressed_fileext_magic matching) ──
#
# Test data: test/files/magic/ contains small compressed files, each holding
# a single byte 'x'.  Created with standard CLI tools:
#
#   echo -n x | gzip -n  > byte.gz     # -n omits filename/timestamp
#   echo -n x | bzip2    > byte.bz2
#   echo -n x | xz       > byte.xz
#   echo -n x | zstd -q  > byte.zst
#   echo -n x > 0                      # zip needs a file on disk
#   touch -t 200001010000.00 0         # fixed timestamp for reproducibility
#   TZ=UTC zip -0 -j byte.zip 0       # -0 store, -j junk paths
#   rm 0
#
# In Python (bz2 is byte-identical to CLI; others differ in internal
# flags but are functionally equivalent):
#   gzip.compress(b'x', mtime=0)
#   bz2.compress(b'x')
#   lzma.compress(b'x', format=lzma.FORMAT_XZ)
#   zstandard.ZstdCompressor().compress(b'x')


@pytest.mark.parametrize('ext, content_file', [
    ('gz', 'files/magic/byte.gz'),
    ('tgz', 'files/magic/byte.gz'),   # tgz is gzip too
    ('bz2', 'files/magic/byte.bz2'),
    ('xz', 'files/magic/byte.xz'),
    ('zst', 'files/magic/byte.zst'),
    ('zstd', 'files/magic/byte.zst'),  # .zstd is the same format
    ('zip', 'files/magic/byte.zip'),
])
def test_file_ext_consistent(sourcescheck, ext, content_file):
    """Extension matches actual compression format → no warning."""
    output, test = sourcescheck
    pkg = get_tested_mock_package(
        files={f'archive.{ext}': {'content-path': content_file}},
    )
    test.check_source(pkg)
    out = output.print_results(output.results)
    assert 'inconsistent-file-extension' not in out


@pytest.mark.parametrize('ext, content_file', [
    ('gz', 'files/magic/byte.bz2'),
    ('bz2', 'files/magic/byte.gz'),
    ('xz', 'files/magic/byte.zst'),
    ('zst', 'files/magic/byte.gz'),
    ('zstd', 'files/magic/byte.xz'),
    ('zip', 'files/magic/byte.gz'),
])
def test_file_ext_inconsistent(sourcescheck, ext, content_file):
    """Extension does NOT match actual compression format → warning."""
    output, test = sourcescheck
    pkg = get_tested_mock_package(
        files={f'archive.{ext}': {'content-path': content_file}},
    )
    test.check_source(pkg)
    out = output.print_results(output.results)
    assert 'inconsistent-file-extension' in out


@pytest.mark.parametrize('fname', [
    'archive.gz',
    'archive.tar',
    'archive.txt',
])
def test_file_ext_no_magic(sourcescheck, fname):
    """File with no magic string (empty content) → no crash, no warning."""
    output, test = sourcescheck
    pkg = get_tested_mock_package(
        files={fname: {'metadata': {'magic': None}}},
    )
    test.check_source(pkg)
    out = output.print_results(output.results)
    assert 'inconsistent-file-extension' not in out


def test_file_ext_unknown_extension(sourcescheck):
    """Extension not in compressed_fileext_magic → no warning."""
    output, test = sourcescheck
    pkg = get_tested_mock_package(
        files={'archive.lz4': {'content-path': 'files/magic/byte.gz'}},
    )
    test.check_source(pkg)
    out = output.print_results(output.results)
    assert 'inconsistent-file-extension' not in out
