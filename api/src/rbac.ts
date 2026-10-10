import { Role } from './types.js';

export type Permission =
  | 'events:read' | 'events:write' | 'alerts:read' | 'incidents:read' | 'incidents:write'
  | 'analysis:request' | 'actions:read' | 'actions:propose' | 'actions:approve' | 'audit:read' | 'dashboard:read' | 'users:manage' | 'retention:run';

const READ: Permission[] = ['events:read', 'alerts:read', 'incidents:read', 'actions:read', 'dashboard:read'];
const ANALYST: Permission[] = [...READ, 'events:write', 'incidents:write', 'analysis:request', 'actions:propose'];

export const PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  viewer: new Set(READ),
  ingestor: new Set<Permission>(['events:write']),
  analyst: new Set(ANALYST),
  approver: new Set<Permission>([...ANALYST, 'actions:approve']),
  auditor: new Set<Permission>([...READ, 'audit:read']),
  admin: new Set<Permission>([...ANALYST, 'actions:approve', 'audit:read', 'users:manage', 'retention:run']),
};

export const can = (role: Role, p: Permission) => PERMISSIONS[role]?.has(p) ?? false;
