# IOC Graph Engine

The IOC Graph Engine transforms individual email analyses into a global
infrastructure intelligence network. It maps relationships between emails,
IP addresses, domains, and files.

## Core Capabilities

1. **Nexus Discovery**: Automatically links disparate emails that share common
   infrastructure (e.g., same originating IP or same payload URL).
2. **Campaign Tracking**: Clusters related events into "Campaigns" based on
   shared indicators of compromise.
3. **Historical Context**: Tracks the first and last seen timestamps for every IOC,
   allowing for maturity-based risk assessment.

## Schema Highlights

- `ioc_nodes`: Individual entities (IP, Domain, URL, Hash).
- `ioc_relations`: Directed links (Extracted from, Hosted on, Resolved to).
- `campaign_clusters`: Logical groupings of high-confidence related threats.

## Performance Considerations

- **Upsert Logic**: Uses SQLite `ON CONFLICT` to minimize round-trips.
- **Indexed Lookups**: Unique indexes on IOC values for O(1) matching.
