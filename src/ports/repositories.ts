import type { AuditRecord, Device, JitGrant, MeshNode, NetworkPolicy, SecurityEvent, UUID } from "../domain/types.js";
export interface DeviceRepository { get(id:UUID):Promise<Device|undefined>; findByHardwareId(id:string):Promise<Device|undefined>; save(value:Device):Promise<void>; list():Promise<Device[]>; }
export interface NodeRepository { get(id:UUID):Promise<MeshNode|undefined>; findByPublicKey(key:string):Promise<MeshNode|undefined>; save(value:MeshNode):Promise<void>; list():Promise<MeshNode[]>; }
export interface PolicyRepository { get(id:UUID):Promise<NetworkPolicy|undefined>; save(value:NetworkPolicy):Promise<void>; listActive():Promise<NetworkPolicy[]>; }
export interface JitRepository { get(id:UUID):Promise<JitGrant|undefined>; save(value:JitGrant):Promise<void>; listActive(now:Date):Promise<JitGrant[]>; }
export interface EventRepository { append(value:SecurityEvent):Promise<void>; recent(limit:number):Promise<SecurityEvent[]>; }
export interface AuditRepository { append(value:AuditRecord):Promise<void>; last():Promise<AuditRecord|undefined>; list():Promise<AuditRecord[]>; }
export interface UnitOfWork { transaction<T>(work:()=>Promise<T>):Promise<T>; }
