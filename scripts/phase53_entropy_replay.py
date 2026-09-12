"""Pinned, opt-in guest-ADT entropy replay for Phase 5.3 experiments."""
import hashlib
from pathlib import Path
import struct


SOURCE_ATTEMPT = 108
SOURCE_RELATIVE_PATH = Path(
    'artifacts/runs/observe-sprr/attempt-108/runs/'
    '7a3f31c3-d728-422a-8bb5-04a2e27ffba0/inputs/guest-device-tree.adt')
SOURCE_SHA256 = 'f087bbbc1b28ead7b60dcf788acc1d1ed0dd94ee7c8ba811c110336510654dbd'
SOURCE_SIZE = 445024
CONFIG_EVIDENCE_FIELD = 'xnu_phase53_adt_entropy_replay_evidence'
PROPERTY_SPECS = {
    'random-seed': ('bytes', 256),
    'cl4-entropy': ('bytes', 192),
    'boot-nonce': ('u64le', 8),
}


def config_evidence():
    """Return stable evidence embedded in an enabled pipeline configuration."""
    return {
        'source_attempt': SOURCE_ATTEMPT,
        'source_path': str(SOURCE_RELATIVE_PATH),
        'source_sha256': SOURCE_SHA256,
        'source_size': SOURCE_SIZE,
        'properties': ['/chosen/' + name for name in PROPERTY_SPECS],
    }


def materialize_config_evidence(config):
    """Add pinned evidence to enabled configs and reject stale/manual variants."""
    result = dict(config)
    enabled = result.get('xnu_phase53_adt_entropy_replay', False)
    supplied = result.get(CONFIG_EVIDENCE_FIELD)
    if enabled:
        expected = config_evidence()
        if supplied is not None and supplied != expected:
            raise ValueError('xnu_phase53_adt_entropy_replay evidence does not match pinned Attempt108 source')
        result[CONFIG_EVIDENCE_FIELD] = expected
    elif supplied is not None:
        raise ValueError('xnu_phase53_adt_entropy_replay_evidence requires xnu_phase53_adt_entropy_replay')
    return result


def load_pinned_source(repo):
    """Load the exact ignored Attempt108 source, failing closed on identity drift."""
    path = Path(repo).resolve() / SOURCE_RELATIVE_PATH
    try:
        blob = path.read_bytes()
    except OSError as error:
        raise ValueError('Pinned Attempt108 guest ADT is unavailable: ' + str(path)) from error
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SOURCE_SHA256 or len(blob) != SOURCE_SIZE:
        raise ValueError('Pinned Attempt108 guest ADT identity mismatch')
    return blob, {'path': str(path), 'sha256': digest, 'size': len(blob)}


def _property_bytes(name, value):
    kind, expected_size = PROPERTY_SPECS[name]
    if kind == 'bytes':
        if type(value) is not bytes or len(value) != expected_size:
            raise ValueError('/chosen/%s must be exactly %d bytes' %
                             (name, expected_size))
        return value
    if kind == 'u64le':
        if type(value) is not int or not 0 <= value < (1 << 64):
            raise ValueError('/chosen/%s must be a u64' % name)
        return struct.pack('<Q', value)
    raise AssertionError('unhandled Phase 5.3 entropy property kind')


def replay_entropy_properties(target_adt, source_adt, source_identity):
    """Replace only three /chosen values and return non-secret hash evidence."""
    target = target_adt['/chosen']
    source = source_adt['/chosen']
    prepared = {}
    for name in PROPERTY_SPECS:
        if name not in target._properties or name not in source._properties:
            raise ValueError('Missing required Phase 5.3 entropy property: /chosen/' + name)
        prepared[name] = (_property_bytes(name, target._properties[name]),
                          _property_bytes(name, source._properties[name]))
    records = {}
    for name in PROPERTY_SPECS:
        before, replacement = prepared[name]
        target._properties[name] = source._properties[name]
        after = _property_bytes(name, target._properties[name])
        before_sha = hashlib.sha256(before).hexdigest()
        source_sha = hashlib.sha256(replacement).hexdigest()
        after_sha = hashlib.sha256(after).hexdigest()
        if after_sha != source_sha:
            raise ValueError('Phase 5.3 entropy replay verification failed: /chosen/' + name)
        records[name] = {
            'path': '/chosen/' + name,
            'size': len(after),
            'before_sha256': before_sha,
            'source_sha256': source_sha,
            'after_sha256': after_sha,
            'changed': before_sha != after_sha,
        }
    return {
        'requested': True,
        'applied': True,
        'mode': 'pinned-attempt-108-guest-adt-entropy-only',
        'source_attempt': SOURCE_ATTEMPT,
        'source': dict(source_identity),
        'properties': records,
        'property_count': len(records),
        'other_properties_modified_by_replay': False,
    }
