import logging

_current_phase = 'INIT'

PHASE_SEQUENCE = [
    'INIT',
    'LDAPX',
    'AUTH',
    'CONNECT',
    'SCHEMA',
    'PREFETCH',
    'USERS',
    'GROUPS',
    'GPOS',
    'OUS',
    'CONTAINERS',
    'COMPUTERS',
    'DOMAINS',
    'HOSTS',
    'OUTPUT',
]


def set_phase(phase):
    global _current_phase
    _current_phase = phase


def get_phase():
    return _current_phase


class PhaseFormatter(logging.Formatter):
    def format(self, record):
        phase = _current_phase
        record.msg = '[%s][%s] %s' % (phase, record.levelname, record.msg)
        record.levelname = ''
        return super().format(record)


class PhaseFileFormatter(logging.Formatter):
    def format(self, record):
        phase = _current_phase
        record.msg = '[%s][%s] %s' % (phase, record.levelname, record.msg)
        record.levelname = ''
        return super().format(record)


def build_phase_sequence(collect, has_ldapx):
    """Return the ordered list of phases that will actually run."""
    phases = ['INIT']
    if has_ldapx:
        phases.append('LDAPX')
    phases.extend(['AUTH', 'CONNECT'])

    has_membership = 'group' in collect or 'objectprops' in collect or 'acl' in collect
    has_container = 'container' in collect
    do_computer_enum = any(m in collect for m in ['localadmin', 'session', 'loggedon', 'experimental', 'rdp', 'dcom', 'psremote'])

    if has_membership or has_container or do_computer_enum:
        phases.extend(['SCHEMA', 'PREFETCH'])
    elif 'trusts' in collect:
        pass

    if has_membership:
        phases.extend(['USERS', 'GROUPS'])
        if has_container:
            phases.extend(['GPOS', 'OUS', 'CONTAINERS'])
        if not do_computer_enum:
            phases.append('COMPUTERS')
    elif has_container:
        phases.extend(['GPOS', 'OUS', 'CONTAINERS'])

    if 'trusts' in collect or 'acl' in collect or 'objectprops' in collect:
        phases.append('DOMAINS')

    if do_computer_enum:
        phases.append('HOSTS')

    phases.append('OUTPUT')
    return phases
