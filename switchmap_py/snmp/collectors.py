from __future__ import annotations

from dataclasses import dataclass

from switchmap_py.config import SwitchConfig
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.model.vlan import Vlan
from switchmap_py.snmp import mibs
from switchmap_py.snmp.session import SnmpConfig, SnmpSession


@dataclass
class PortSnapshot:
    name: str
    is_active: bool
    mac_count: int
    oper_status: str


def build_session(switch: SwitchConfig, timeout: int, retries: int) -> SnmpSession:
    return SnmpSession(
        SnmpConfig(
            hostname=switch.management_ip,
            version=switch.snmp_version,
            community=switch.community,
            timeout=timeout,
            retries=retries,
        )
    )


def _normalize_status(value: str) -> str:
    return {"1": "up", "2": "down"}.get(value, value)


def collect_switch_state(
    switch: SwitchConfig, timeout: int, retries: int
) -> Switch:
    session = build_session(switch, timeout, retries)
    names = session.get_table(mibs.IF_NAME)
    descrs = session.get_table(mibs.IF_DESCR)
    admin = session.get_table(mibs.IF_ADMIN_STATUS)
    oper = session.get_table(mibs.IF_OPER_STATUS)
    speeds = session.get_table(mibs.IF_SPEED)

    ports: list[Port] = []
    for oid, name in names.items():
        index = oid.split(".")[-1]
        descr = descrs.get(f"{mibs.IF_DESCR}.{index}", "")
        admin_status = _normalize_status(admin.get(f"{mibs.IF_ADMIN_STATUS}.{index}", ""))
        oper_status = _normalize_status(oper.get(f"{mibs.IF_OPER_STATUS}.{index}", ""))
        speed = speeds.get(f"{mibs.IF_SPEED}.{index}")
        ports.append(
            Port(
                name=name,
                descr=descr,
                admin_status=admin_status,
                oper_status=oper_status,
                speed=int(speed) if speed and speed.isdigit() else None,
                vlan=None,
                macs=[],
                idle_since=None,
                last_active=None,
                is_trunk=name in switch.trunk_ports,
            )
        )

    vlans: list[Vlan] = []
    try:
        vlan_names = session.get_table(mibs.QBRIDGE_VLAN_NAME)
    except Exception:
        vlan_names = {}
    for oid, vlan_name in vlan_names.items():
        vlan_id = oid.split(".")[-1]
        vlans.append(Vlan(vlan_id=vlan_id, name=vlan_name, ports=[]))

    return Switch(
        name=switch.name,
        management_ip=switch.management_ip,
        vendor=switch.vendor,
        ports=ports,
        vlans=vlans,
    )


def collect_port_snapshots(
    switch: SwitchConfig, timeout: int, retries: int
) -> list[PortSnapshot]:
    state = collect_switch_state(switch, timeout, retries)
    snapshots: list[PortSnapshot] = []
    for port in state.ports:
        snapshots.append(
            PortSnapshot(
                name=port.name,
                is_active=port.is_active,
                mac_count=len(port.macs),
                oper_status=port.oper_status,
            )
        )
    return snapshots
