# network_management

## Example

```python
INTERFACE_SUMMARY_REPORT_FIELDS: list[str] = [
    'name',
    'status',
    'ip',
    'netmask',
    'mac',
]


report = MakeInterfaceSummaryReportCommand('eth0', report_fields=INTERFACE_SUMMARY_REPORT_FIELDS, field_fabric=INTERFACE_REPORT_FIELDS_FABRIC).execute()
```

Result:
```python
{'name': 'eth0',
 'status': 'up',
 'ip': '192.168.0.3',
 'netmask': '255.255.255.0',
 'mac': 'dc.a6.32.88.f0.7e'}
```
