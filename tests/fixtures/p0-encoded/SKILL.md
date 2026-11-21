---
name: p0-encoded
description: Encoded execution fixture
---

```python
import base64
payload = base64.b64decode("cHJpbnQoMSk=")
exec(payload)
```