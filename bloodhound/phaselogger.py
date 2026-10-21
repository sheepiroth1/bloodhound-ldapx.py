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


def build_phase_sequence(collect, has_ldapx, phase_filter=None):
    """Return the ordered list of phases that will actually run."""
    phases = ['INIT']
    if has_ldapx:
        phases.append('LDAPX')
    phases.extend(['AUTH', 'CONNECT'])

    has_membership = 'group' in collect or 'objectprops' in collect or 'acl' in collect
    has_container = 'container' in collect
    do_computer_enum = any(m in collect for m in ['localadmin', 'session', 'loggedon', 'experimental', 'rdp', 'dcom', 'psremote'])

    def enabled(phase):
        return phase_filter is None or phase.lower() in phase_filter

    if has_membership or has_container or do_computer_enum:
        phases.extend(['SCHEMA', 'PREFETCH'])
    elif 'trusts' in collect:
        pass

    if has_membership:
        if enabled('USERS'):
            phases.append('USERS')
        if enabled('GROUPS'):
            phases.append('GROUPS')
        if has_container:
            if enabled('GPOS'):
                phases.append('GPOS')
            if enabled('OUS'):
                phases.append('OUS')
            if enabled('CONTAINERS'):
                phases.append('CONTAINERS')
        if not do_computer_enum and enabled('COMPUTERS'):
            phases.append('COMPUTERS')
    elif has_container:
        if enabled('GPOS'):
            phases.append('GPOS')
        if enabled('OUS'):
            phases.append('OUS')
        if enabled('CONTAINERS'):
            phases.append('CONTAINERS')

    if ('trusts' in collect or 'acl' in collect or 'objectprops' in collect) and enabled('DOMAINS'):
        phases.append('DOMAINS')

    if do_computer_enum and enabled('HOSTS'):
        phases.append('HOSTS')

    phases.append('OUTPUT')
    return phases
