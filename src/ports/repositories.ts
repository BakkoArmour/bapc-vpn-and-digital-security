import type { AuditRecord, Device, JitGrant, MeshNode, NetworkPolicy, SecurityEvent, UUID } from "../domain/types.js";
// listAll() — not list() — for the same reason AuditRepository uses chain():
// this class also implements NodeRepository, which already owns list() with
// a different return type. PgRepositories' single list() always queries
// mesh_nodes; SocService.snapshot()'s `this.devices.list()` was silently
// reading node rows as if they were devices — MeshNode has no .revoked or
// .compromised field, so revokedDevices/compromisedDevices on
// GET /api/v1/soc/snapshot were always 0 regardless of reality.
export interface DeviceRepository { get(id:UUID):Promise<Device|undefined>; findByHardwareId(id:string):Promise<Device|undefined>; save(value:Device):Promise<void>; listAll():Promise<Device[]>; }
export interface NodeRepository { get(id:UUID):Promise<MeshNode|undefined>; findByPublicKey(key:string):Promise<MeshNode|undefined>; save(value:MeshNode):Promise<void>; list():Promise<MeshNode[]>; }
export interface PolicyRepository { get(id:UUID):Promise<NetworkPolicy|undefined>; save(value:NetworkPolicy):Promise<void>; listActive():Promise<NetworkPolicy[]>; }
export interface JitRepository { get(id:UUID):Promise<JitGrant|undefined>; save(value:JitGrant):Promise<void>; listActive(now:Date):Promise<JitGrant[]>; }
export interface EventRepository { append(value:SecurityEvent):Promise<void>; recent(limit:number):Promise<SecurityEvent[]>; }
// chain() — not list() — deliberately: this class also implements
// DeviceRepository/NodeRepository, both of which already declare a
// same-named list() with a different return type. A single class can only
// have one `list` method, so the two silently collided (TypeScript's `any`
// return type on the shared implementation hid it) — AuditService.verify()
// was calling what was actually NodeRepository.list(), walking an empty or
// wrong array and always returning true. See PgRepositories/MemoryStore.
export interface AuditRepository { append(value:AuditRecord):Promise<void>; last():Promise<AuditRecord|undefined>; chain():Promise<AuditRecord[]>; }
export interface UnitOfWork { transaction<T>(work:()=>Promise<T>):Promise<T>; }
