# network_management

## Example

```python
from network_var1 import MakeInterfaceSummaryReportCommand
from network_var1 import INTERFACE_REPORT_FIELDS_FABRIC as var1_fabric
from network_var2 import INTERFACE_REPORT_FIELDS_FABRIC as var2_fabric


INTERFACE_SUMMARY_REPORT_FIELDS: list[str] = [
    'name',
    'status',
    'ip',
    'netmask',
    'mac',
]


report_var1 = MakeInterfaceSummaryReportCommand('eth0', report_fields=INTERFACE_SUMMARY_REPORT_FIELDS, field_fabric=var1_fabric).execute()
print(report_var1)

report_var2 = MakeInterfaceSummaryReportCommand('eth0', report_fields=INTERFACE_SUMMARY_REPORT_FIELDS, field_fabric=var2_fabric).execute()
print(report_var2)

```

Result:

```python
{'name': 'eth0',
 'status': 'up',
 'ip': '192.168.0.3',
 'netmask': '255.255.255.0',
 'mac': 'dc.a6.32.88.f0.7e'}
```
