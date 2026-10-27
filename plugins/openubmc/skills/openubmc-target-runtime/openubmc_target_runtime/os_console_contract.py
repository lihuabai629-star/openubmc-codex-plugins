"""Fixed host observations reached through a BMC's serial console."""
from collections.abc import Mapping


def validate_os_console_names(names):
    if (not isinstance(names, (tuple, list)) or not 1 <= len(names) <= 2
            or any(name not in ('identity', 'network') for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('os_console names require distinct identity and/or network probes')


def os_console_summary(child):
    """Keep OS identity separate from BMC identity and its target epoch."""
    result = {'transport': child.get('transport', 'bmc-ssh-sol'), 'identity': child.get('identity'),
              'gaps': child.get('gaps', ['os_console_not_collected'])}
    network = child.get('network')
    if isinstance(network, Mapping):
        interfaces = network.get('interfaces', [])
        routes = network.get('routes', [])
        result['network'] = {'interfaces': interfaces[:16], 'routes': routes[:16],
                             'projection_truncated': len(interfaces) > 16 or len(routes) > 16}
    return result
