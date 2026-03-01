# YaraForge System Architecture Overview

```mermaid
  graph TD;
      CLI --> Engine;
      Engine --> Deploy;
      Engine --> Report;
      Engine --> Scanner;
      Scanner --> target systems;
```