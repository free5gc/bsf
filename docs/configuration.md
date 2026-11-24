# NRF registration PLMNs

Set `configuration.plmnList` to advertise the PLMNs served by this BSF:

```yaml
configuration:
  plmnList:
    - mcc: "001"
      mnc: "01"
    - mcc: "001"
      mnc: "001"
```

Omitting the field (or setting it to null) preserves the previous `208/93`
registration. An explicit empty list is rejected. MCC must contain three
decimal digits; MNC must contain two or three. Quote values to preserve leading
zeros. This changes the BSF profile registered with NRF, not the PLMNs of other
NFs, RANs or subscribers.
